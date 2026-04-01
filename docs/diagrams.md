# supplyify Architecture Diagrams

## System Architecture

High-level view of how supplyify's detection layers work together.

```mermaid
graph TB
    CLI["supplyify scan ."]

    subgraph Discovery["Project Discovery"]
        NPM["npm Parser<br/>package-lock.json<br/>yarn.lock<br/>pnpm-lock.yaml"]
        CARGO["Cargo Parser<br/>Cargo.lock"]
        PIP["pip Parser<br/>requirements.txt<br/>poetry.lock<br/>Pipfile.lock"]
    end

    subgraph Layer1["Layer 1: Known Threats"]
        L1A["Layer 1a: Indicators<br/>Bundled TOML database<br/>~3ms, offline"]
        L1B["Layer 1b: OSV.dev<br/>80K+ advisories<br/>~500ms, online"]
    end

    subgraph Layer2["Layer 2: Heuristics"]
        POST["Postinstall Scripts<br/>lifecycle script analysis"]
        VER["Version Anomalies<br/>non-semver detection"]
    end

    MERGE["Finding Merge<br/>dedup + sort by severity"]

    subgraph Output["Output Formats"]
        TEXT["Text<br/>colored terminal"]
        JSON["JSON<br/>structured data"]
        AGENT["Agent<br/>pipe-delimited<br/>for LLMs"]
    end

    EXIT["Exit Code<br/>0=clean 1=critical 2=warn"]

    CLI --> Discovery
    NPM --> L1A
    CARGO --> L1A
    PIP --> L1A
    L1A --> MERGE
    L1B --> MERGE
    POST --> MERGE
    VER --> MERGE
    NPM --> L1B
    CARGO --> L1B
    PIP --> L1B
    NPM --> POST
    NPM --> VER
    MERGE --> Output
    Output --> EXIT

    style L1A fill:#2d5016,color:#fff
    style L1B fill:#1a3a5c,color:#fff
    style POST fill:#5c3a1a,color:#fff
    style VER fill:#5c3a1a,color:#fff
    style MERGE fill:#4a1a4a,color:#fff
```

## Scan Data Flow

Step-by-step flow of a single `supplyify scan .` invocation.

```mermaid
flowchart LR
    A[Project Path] --> B{Lockfiles<br/>Found?}
    B -->|No| Z1[Exit 0<br/>No lockfiles]
    B -->|Yes| C[Parse Lockfiles]
    C --> D["Vec&lt;Dependency&gt;"]

    D --> E[Layer 1a:<br/>Indicator Match]
    D --> F[Layer 1b:<br/>OSV Batch Query]
    D --> G[Layer 2:<br/>Heuristics]

    E --> H[Findings]
    F --> H
    G --> H

    H --> I{Any Critical<br/>or High?}
    I -->|Yes| Z2[Exit 1]
    I -->|No| J{Any Medium<br/>or Low?}
    J -->|Yes| Z3[Exit 2]
    J -->|No| Z4[Exit 0<br/>Clean]

    style E fill:#2d5016,color:#fff
    style F fill:#1a3a5c,color:#fff
    style G fill:#5c3a1a,color:#fff
    style Z2 fill:#8b0000,color:#fff
    style Z3 fill:#8b8b00,color:#000
    style Z4 fill:#006400,color:#fff
```

## Sweep Mode

How `supplyify sweep ~/projects` discovers and scans multiple projects in parallel.

```mermaid
flowchart TB
    ROOT["Root Directory<br/>~/projects"] --> WALK["WalkDir<br/>skip: node_modules, target,<br/>.git, __pycache__, venv"]
    WALK --> DETECT{"Lockfile<br/>found?"}
    DETECT -->|package-lock.json| P1["Project 1"]
    DETECT -->|Cargo.lock| P2["Project 2"]
    DETECT -->|requirements.txt| P3["Project 3"]
    DETECT -->|yarn.lock| P4["Project N..."]

    subgraph Rayon["Rayon Thread Pool (--parallel N)"]
        P1 --> S1["scan()"]
        P2 --> S2["scan()"]
        P3 --> S3["scan()"]
        P4 --> S4["scan()"]
    end

    S1 --> AGG["Aggregate Results"]
    S2 --> AGG
    S3 --> AGG
    S4 --> AGG

    AGG --> OUT["Per-Project Summary<br/>+ Total Stats<br/>+ Worst Exit Code"]
```

## Indicator Database

How indicators are loaded, merged, and indexed for fast lookups.

```mermaid
flowchart LR
    subgraph Sources["Indicator Sources"]
        BUNDLED["Bundled TOML<br/>include_str!<br/>compiled into binary"]
        USER["User Config<br/>~/.config/supplyify/<br/>indicators.toml"]
        REMOTE["Remote Feed<br/>supplyify update<br/>GitHub TOML"]
    end

    BUNDLED --> MERGE["Merge<br/>union, dedup by<br/>package+version"]
    USER --> MERGE
    REMOTE -->|"update cmd"| USER

    MERGE --> DB["IndicatorDb"]

    DB --> VI["version_index<br/>HashMap&lt;(eco,pkg,ver), MV&gt;<br/>O(1) lookup"]
    DB --> PI["package_index<br/>HashMap&lt;(eco,pkg), MP&gt;<br/>O(1) lookup"]
    DB --> RI["range_check<br/>semver comparison<br/>O(n) scan"]

    style BUNDLED fill:#2d5016,color:#fff
    style USER fill:#1a3a5c,color:#fff
    style REMOTE fill:#5c3a1a,color:#fff
```

## Module Structure

```mermaid
graph TB
    subgraph CLI["CLI Layer"]
        MAIN["main.rs<br/>clap 4 derive"]
        CMDS["commands/<br/>scan, sweep, check,<br/>indicators, update"]
    end

    subgraph Core["Core Library"]
        LIB["lib.rs<br/>Config, Severity,<br/>Ecosystem, Finding,<br/>ScanResult"]
        SCANNER["scanner.rs<br/>3-layer orchestration"]
        SWEEP["sweep.rs<br/>project discovery<br/>+ rayon parallel"]
        OSV["osv.rs<br/>OSV.dev batch API"]
    end

    subgraph Parsers["Ecosystem Parsers"]
        EMOD["ecosystems/mod.rs<br/>EcosystemParser trait"]
        ENPM["npm.rs"]
        ECARGO["cargo.rs"]
        EPIP["pip.rs"]
    end

    subgraph Detection["Detection"]
        IND["indicators/mod.rs<br/>IndicatorDb"]
        BUNDLED2["bundled.toml"]
        HMOD["heuristics/mod.rs"]
        HPOST["postinstall.rs"]
        HVER["version.rs"]
    end

    subgraph Format["Output"]
        OMOD["output/mod.rs"]
        OTEXT["text.rs"]
        OJSON["json.rs"]
        OAGENT["agent.rs"]
    end

    MAIN --> CMDS
    CMDS --> SCANNER
    CMDS --> SWEEP
    SCANNER --> EMOD
    SCANNER --> IND
    SCANNER --> OSV
    SCANNER --> HMOD
    EMOD --> ENPM
    EMOD --> ECARGO
    EMOD --> EPIP
    IND --> BUNDLED2
    HMOD --> HPOST
    HMOD --> HVER
    CMDS --> OMOD
    OMOD --> OTEXT
    OMOD --> OJSON
    OMOD --> OAGENT

    style SCANNER fill:#4a1a4a,color:#fff
    style IND fill:#2d5016,color:#fff
    style OSV fill:#1a3a5c,color:#fff
```

## OSV.dev Integration

Sequence diagram for the OSV batch query flow.

```mermaid
sequenceDiagram
    participant S as Scanner
    participant O as osv.rs
    participant API as api.osv.dev

    S->>O: query_batch(deps)

    loop Chunks of 1000
        O->>O: Build OsvBatchRequest
        O->>API: POST /v1/querybatch<br/>{queries: [{package, version}...]}
        API-->>O: {results: [{vulns: [...]}]}
        O->>O: Map OsvVuln to Finding<br/>MAL- prefix = Critical<br/>GHSA- = check severity
    end

    O-->>S: Vec<Finding>
```

## Finding Severity Classification

```mermaid
stateDiagram-v2
    [*] --> Scan

    Scan --> Clean: No findings
    Scan --> Critical: malicious_version OR MAL- prefix
    Scan --> High: CVSS >= 7.0 OR obfuscation + postinstall
    Scan --> Medium: CVSS >= 4.0 OR version anomaly
    Scan --> Low: CVSS < 4.0 OR informational

    Critical --> Exit1: exit code 1
    High --> Exit1
    Medium --> Exit2: exit code 2
    Low --> Exit2
    Clean --> Exit0: exit code 0
```

---

*Diagrams render natively on GitHub, in VS Code (with Mermaid Preview extension), and at [mermaid.live](https://mermaid.live).*
