//! Plugin system for extending supplyify with enterprise features.
//!
//! The core defines the Plugin trait (MIT licensed). Enterprise plugins
//! implement this trait in a separate proprietary crate and are loaded
//! at runtime via shared libraries or compiled in as optional features.
//!
//! # Architecture
//!
//! ```text
//! supplyify (MIT)           supplyify-enterprise (proprietary)
//! ┌──────────────────┐      ┌──────────────────────────┐
//! │ Plugin trait      │◄─────│ PriorityFeedPlugin       │
//! │ PluginContext     │      │ PolicyEnginePlugin        │
//! │ PluginManifest    │      │ DashboardReporterPlugin   │
//! │ load_plugins()    │      │ SbomExportPlugin          │
//! └──────────────────┘      └──────────────────────────┘
//! ```

use crate::{Config, Dependency, Finding, ScanResult};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Capability that a plugin provides
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Additional indicator sources (priority feed, private indicators)
    IndicatorSource,
    /// Policy enforcement (allowed/blocked packages, org rules)
    PolicyEngine,
    /// Additional output formats (SARIF, SBOM, dashboard reporting)
    OutputFormat,
    /// Post-scan actions (alerting, ticket creation, dashboard sync)
    PostScan,
    /// Pre-scan enrichment (dependency metadata, license info)
    PreScan,
}

/// Metadata about a plugin
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<PluginCapability>,
    pub author: String,
    pub license: String,
}

/// Context passed to plugins during execution
pub struct PluginContext<'a> {
    pub config: &'a Config,
    pub project_path: &'a Path,
    pub dependencies: &'a [Dependency],
}

/// Result of a plugin's indicator check
pub struct PluginIndicatorResult {
    pub findings: Vec<Finding>,
    pub source_name: String,
}

/// Result of a plugin's policy evaluation
pub struct PolicyResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub findings: Vec<Finding>,
}

/// The core plugin trait. Enterprise plugins implement this.
///
/// All methods have default no-op implementations so plugins only need
/// to implement the capabilities they provide.
pub trait Plugin: Send + Sync {
    /// Plugin metadata
    fn manifest(&self) -> &PluginManifest;

    /// Initialize the plugin (called once at startup)
    fn init(&mut self, _config: &Config) -> Result<()> {
        Ok(())
    }

    /// Provide additional indicators for scanning (IndicatorSource capability)
    fn check_indicators(
        &self,
        _ctx: &PluginContext,
        _deps: &[&Dependency],
    ) -> Result<PluginIndicatorResult> {
        Ok(PluginIndicatorResult {
            findings: vec![],
            source_name: self.manifest().name.clone(),
        })
    }

    /// Evaluate organizational policy (PolicyEngine capability)
    fn evaluate_policy(&self, _ctx: &PluginContext, _deps: &[&Dependency]) -> Result<PolicyResult> {
        Ok(PolicyResult {
            allowed: true,
            reason: None,
            findings: vec![],
        })
    }

    /// Format results in a custom output format (OutputFormat capability)
    fn format_output(&self, _results: &[ScanResult]) -> Result<Option<String>> {
        Ok(None)
    }

    /// Run post-scan actions (PostScan capability)
    fn post_scan(&self, _ctx: &PluginContext, _results: &[ScanResult]) -> Result<()> {
        Ok(())
    }
}

/// Plugin registry — discovers and loads plugins
pub struct PluginRegistry {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginRegistry {
    /// Create empty registry
    pub fn new() -> Self {
        Self { plugins: vec![] }
    }

    /// Register a plugin
    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    /// Load plugins from the plugin directory
    ///
    /// Plugin directory: ~/.config/supplyify/plugins/
    /// Each plugin is a directory containing a manifest.toml
    pub fn discover() -> Self {
        let registry = Self::new();

        if let Some(plugin_dir) = plugin_directory() {
            if plugin_dir.exists() {
                // Future: load shared libraries or WASM plugins from this directory
                // For now, enterprise plugins are compiled in as optional features
                let _ = plugin_dir; // Placeholder for dynamic loading
            }
        }

        registry
    }

    /// Get all registered plugins
    pub fn plugins(&self) -> &[Box<dyn Plugin>] {
        &self.plugins
    }

    /// Get plugins with a specific capability
    pub fn with_capability(&self, cap: &PluginCapability) -> Vec<&dyn Plugin> {
        self.plugins
            .iter()
            .filter(|p| p.manifest().capabilities.contains(cap))
            .map(|p| p.as_ref())
            .collect()
    }

    /// Run all indicator source plugins
    pub fn check_all_indicators(&self, ctx: &PluginContext, deps: &[&Dependency]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for plugin in self.with_capability(&PluginCapability::IndicatorSource) {
            match plugin.check_indicators(ctx, deps) {
                Ok(result) => findings.extend(result.findings),
                Err(e) => {
                    eprintln!("Plugin {} error: {}", plugin.manifest().name, e);
                }
            }
        }
        findings
    }

    /// Run all policy engine plugins
    pub fn evaluate_all_policies(&self, ctx: &PluginContext, deps: &[&Dependency]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for plugin in self.with_capability(&PluginCapability::PolicyEngine) {
            match plugin.evaluate_policy(ctx, deps) {
                Ok(result) => findings.extend(result.findings),
                Err(e) => {
                    eprintln!("Plugin {} error: {}", plugin.manifest().name, e);
                }
            }
        }
        findings
    }

    /// Run all post-scan plugins
    pub fn run_post_scan(&self, ctx: &PluginContext, results: &[ScanResult]) {
        for plugin in self.with_capability(&PluginCapability::PostScan) {
            if let Err(e) = plugin.post_scan(ctx, results) {
                eprintln!("Plugin {} post-scan error: {}", plugin.manifest().name, e);
            }
        }
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin directory: ~/.config/supplyify/plugins/
fn plugin_directory() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("supplyify").join("plugins"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    struct MockPlugin {
        manifest: PluginManifest,
    }

    impl MockPlugin {
        fn new(name: &str, caps: Vec<PluginCapability>) -> Self {
            Self {
                manifest: PluginManifest {
                    name: name.to_string(),
                    version: "0.1.0".to_string(),
                    description: "Test plugin".to_string(),
                    capabilities: caps,
                    author: "test".to_string(),
                    license: "proprietary".to_string(),
                },
            }
        }
    }

    impl Plugin for MockPlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
    }

    #[test]
    fn test_registry_capability_filter() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(MockPlugin::new(
            "feed",
            vec![PluginCapability::IndicatorSource],
        )));
        registry.register(Box::new(MockPlugin::new(
            "policy",
            vec![PluginCapability::PolicyEngine],
        )));
        registry.register(Box::new(MockPlugin::new(
            "both",
            vec![
                PluginCapability::IndicatorSource,
                PluginCapability::PolicyEngine,
            ],
        )));

        assert_eq!(
            registry
                .with_capability(&PluginCapability::IndicatorSource)
                .len(),
            2
        );
        assert_eq!(
            registry
                .with_capability(&PluginCapability::PolicyEngine)
                .len(),
            2
        );
        assert_eq!(
            registry
                .with_capability(&PluginCapability::OutputFormat)
                .len(),
            0
        );
    }

    #[test]
    fn test_empty_registry() {
        let registry = PluginRegistry::new();
        assert!(registry.plugins().is_empty());
    }
}
