//! Ghost-Hunter build orchestration.
//!
//! Invoked via `cargo xtask build`. Executes the full cross-compilation
//! pipeline in strict sequence:
//!
//!   1. Verify `bpf-linker` is present on PATH.
//!   2. Compile `gh-probe` for `bpf-unknown-none` (BPF object).
//!   3. Copy artifact to `target/bpf/gh-probe.o`.
//!   4. Compile `gh-analyzer` for the host target.
//!
//! Every step that fails causes an immediate structured error message and
//! process exit(1). No step is skipped or soft-failed.

use std::fs;
use std::path::Path;
use std::process::{self, Command};

fn main() {
    check_bpf_linker();
    build_probe();
    copy_probe_artifact();
    build_analyzer();
}

// ── Step 1: bpf-linker presence check ────────────────────────────────────────

fn check_bpf_linker() {
    let status = Command::new("which")
        .arg("bpf-linker")
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[xtask] error: failed to invoke `which`: {e}");
            eprintln!("[xtask] hint:  ensure `which` is available on PATH");
            process::exit(1);
        });

    if !status.success() {
        eprintln!("[xtask] error: `bpf-linker` not found on PATH");
        eprintln!("[xtask] hint:  install it with:");
        eprintln!("[xtask]          cargo install bpf-linker");
        process::exit(1);
    }
}

// ── Step 2: compile gh-probe for bpf-unknown-none ────────────────────────────

fn build_probe() {
    let status = Command::new("cargo")
        .args([
            "build",
            "-p", "gh-probe",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
            "--release",
        ])
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[xtask] error: failed to spawn `cargo build` for gh-probe: {e}");
            process::exit(1);
        });

    if !status.success() {
        eprintln!("[xtask] error: `cargo build -p gh-probe --target bpf-unknown-none` failed");
        eprintln!("[xtask] hint:  check gh-probe source for BPF compatibility errors");
        process::exit(1);
    }
}

// ── Step 3: copy artifact to target/bpf/gh-probe.o ───────────────────────────

fn copy_probe_artifact() {
    let src = Path::new("target/bpfel-unknown-none/release/gh_probe");
    let dst_dir = Path::new("target/bpf");
    let dst = dst_dir.join("gh-probe.o");

    fs::create_dir_all(dst_dir).unwrap_or_else(|e| {
        eprintln!("[xtask] error: failed to create directory `{}`: {e}", dst_dir.display());
        process::exit(1);
    });

    fs::copy(src, &dst).unwrap_or_else(|e| {
        eprintln!(
            "[xtask] error: failed to copy `{}` → `{}`: {e}",
            src.display(),
            dst.display()
        );
        eprintln!("[xtask] hint:  ensure step 2 (gh-probe build) completed successfully");
        process::exit(1);
    });
}

// ── Step 4: compile gh-analyzer for host ─────────────────────────────────────

fn build_analyzer() {
    let status = Command::new("cargo")
        .args([
            "build",
            "-p", "gh-analyzer",
            "--release",
        ])
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[xtask] error: failed to spawn `cargo build` for gh-analyzer: {e}");
            process::exit(1);
        });

    if !status.success() {
        eprintln!("[xtask] error: `cargo build -p gh-analyzer --release` failed");
        eprintln!("[xtask] hint:  check gh-analyzer source and dependencies");
        process::exit(1);
    }
}