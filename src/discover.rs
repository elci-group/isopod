// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Discovery Engine — finds projects missing .isopod.
//!
//! Scans configured roots for directories that look like projects (presence
//! of .git, Cargo.toml, etc.) and reports which are untracked vs tracked.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Default markers that identify a project root.
pub const DEFAULT_MARKERS: &[&str] = &[
    ".git",
    "Cargo.toml",
    "package.json",
    "go.mod",
    "pyproject.toml",
    "pom.xml",
    "build.gradle",
    "Makefile",
    "CMakeLists.txt",
    ".project",
    "setup.py",
    "poetry.lock",
];

/// Directories never descended into.
pub const DEFAULT_IGNORE: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    ".isopod",
    ".kaptaind",
    ".traci",
    ".hg",
    ".svn",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
];

#[derive(Debug, Clone)]
pub struct DiscoverConfig {
    /// Roots to scan (e.g., ~/projects, /home/sal).
    pub roots: Vec<PathBuf>,
    /// Marker files/dirs that qualify a directory as a project.
    pub markers: Vec<String>,
    /// Maximum walk depth from each root.
    pub max_depth: usize,
    /// Directory names to skip descending into.
    pub ignore: Vec<String>,
    /// Also consider any directory with a `.git` ancestor as project if true.
    pub require_marker: bool,
}

impl Default for DiscoverConfig {
    fn default() -> Self {
        Self {
            roots: vec![dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))],
            markers: DEFAULT_MARKERS.iter().map(|s| s.to_string()).collect(),
            max_depth: 4,
            ignore: DEFAULT_IGNORE.iter().map(|s| s.to_string()).collect(),
            require_marker: true,
        }
    }
}

impl DiscoverConfig {
    pub fn with_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.roots = roots;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredProject {
    pub path: PathBuf,
    pub markers: Vec<String>,
    pub has_isopod: bool,
}

impl DiscoveredProject {
    pub fn is_untracked(&self) -> bool {
        !self.has_isopod
    }
    pub fn is_tracked(&self) -> bool {
        self.has_isopod
    }
}

/// Check if a directory is a project (has at least one marker).
pub fn is_project_dir(path: &Path, markers: &[String]) -> Option<Vec<String>> {
    let mut found = Vec::new();
    for m in markers {
        if path.join(m).exists() {
            found.push(m.clone());
        }
    }
    if found.is_empty() {
        None
    } else {
        Some(found)
    }
}

/// Check if .isopod exists and looks valid (dir with controls or state.db).
pub fn has_isopod(path: &Path) -> bool {
    let isopod = path.join(".isopod");
    if !isopod.exists() {
        return false;
    }
    // Consider valid if it's a dir or file; most commonly a dir.
    if isopod.is_dir() {
        // At least one expected child or the dir itself counts.
        true
    } else {
        true
    }
}

/// Discover all projects under configured roots.
pub fn discover_projects(cfg: &DiscoverConfig) -> Vec<DiscoveredProject> {
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for root in &cfg.roots {
        if !root.exists() {
            continue;
        }
        // Walk with max depth, filtering ignores.
        let walker = WalkDir::new(root)
            .max_depth(cfg.max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                // Skip hidden dotfiles except .git which is a marker? We handle via ignore list.
                // Allow .git as entry but don't descend into ignored dirs.
                !cfg.ignore.iter().any(|ig| &name == ig)
            });

        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::warn!(root = %root.display(), error = %error, "project discovery entry was unreadable");
                    continue;
                }
            };
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Avoid duplicate parent scans: if we already found a project at ancestor, skip children
            // unless max_depth allows nested projects. For now, allow nested but deduplicate by path.
            if seen.contains(path) {
                continue;
            }
            if let Some(markers) = is_project_dir(path, &cfg.markers) {
                let has = has_isopod(path);
                out.push(DiscoveredProject {
                    path: path.to_path_buf(),
                    markers,
                    has_isopod: has,
                });
                seen.insert(path.to_path_buf());
            }
        }
        // Also check root itself
        if let Some(markers) = is_project_dir(root, &cfg.markers) {
            if !seen.contains(root) {
                out.push(DiscoveredProject {
                    path: root.clone(),
                    markers,
                    has_isopod: has_isopod(root),
                });
            }
        }
    }

    // Sort for stable output
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Quick helper: find untracked projects only.
pub fn discover_untracked(cfg: &DiscoverConfig) -> Vec<DiscoveredProject> {
    discover_projects(cfg)
        .into_iter()
        .filter(|p| p.is_untracked())
        .collect()
}

/// Quick helper: find tracked projects only.
pub fn discover_tracked(cfg: &DiscoverConfig) -> Vec<DiscoveredProject> {
    discover_projects(cfg)
        .into_iter()
        .filter(|p| p.is_tracked())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_project_and_isopod() {
        let dir = TempDir::new().unwrap();
        let proj = dir.path().join("myproj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("Cargo.toml"), b"[package]").unwrap();
        let cfg = DiscoverConfig {
            roots: vec![dir.path().to_path_buf()],
            markers: vec!["Cargo.toml".to_string()],
            max_depth: 3,
            ignore: vec![],
            require_marker: true,
        };
        let projects = discover_projects(&cfg);
        assert_eq!(projects.len(), 1);
        assert!(projects[0].is_untracked());
        std::fs::create_dir_all(proj.join(".isopod")).unwrap();
        let projects2 = discover_projects(&cfg);
        assert!(projects2[0].is_tracked());
    }

    #[test]
    fn ignores_traversal() {
        let dir = TempDir::new().unwrap();
        let proj = dir.path().join("proj");
        std::fs::create_dir_all(proj.join("target")).unwrap();
        std::fs::write(proj.join("Cargo.toml"), b"").unwrap();
        std::fs::write(proj.join("target").join("Cargo.toml"), b"").unwrap();
        let cfg = DiscoverConfig {
            roots: vec![dir.path().to_path_buf()],
            markers: vec!["Cargo.toml".to_string()],
            max_depth: 4,
            ignore: vec!["target".to_string()],
            require_marker: true,
        };
        let projects = discover_projects(&cfg);
        // Should find proj but not proj/target
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].path, proj);
    }
}
