//! Emit build-time metadata as `rustc-env` for `pharos_utils::version`.
//!
//! Captures the short git SHA (with `-dirty` suffix if the working tree is
//! dirty), the Rust target triple, and the cargo build profile, then composes
//! the canonical agent string `Pharos/v<pkg>-<sha>/<target>` so downstream
//! consumers (libp2p identify, Beacon API node-version) read a single env
//! var instead of re-running git themselves.

use std::path::Path;
use std::process::Command;

fn git_short_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn working_tree_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

fn rerun_on_git_state() {
    let head = Path::new("../../.git/HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed=../../.git/HEAD");
    }
    let index = Path::new("../../.git/index");
    if index.exists() {
        println!("cargo:rerun-if-changed=../../.git/index");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PHAROS_GIT_SHA_OVERRIDE");
    rerun_on_git_state();

    let sha = std::env::var("PHAROS_GIT_SHA_OVERRIDE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let mut s = git_short_sha();
            if working_tree_dirty() {
                s.push_str("-dirty");
            }
            s
        });

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let pkg_version =
        std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is set by cargo");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=PHAROS_GIT_SHA={sha}");
    println!("cargo:rustc-env=PHAROS_TARGET={target}");
    println!("cargo:rustc-env=PHAROS_PROFILE={profile}");
    println!("cargo:rustc-env=PHAROS_AGENT_STRING=Pharos/v{pkg_version}-{sha}/{target}");
}
