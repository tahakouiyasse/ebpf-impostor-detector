# ebpf-impostor-detector

> Host Intrusion Detection & Active Signaling System (HIDASS) for Linux 5.15+. Detects APT TTY sessions via Stackelberg game-theoretic jitter injection. Built on Rust, eBPF/Aya, and Tokio async runtime with zero-copy RingBuf semantics.

---

## Threat Model

**Adversary class**: Post-exploitation actor with user-level or limited privilege escalation, operating via interactive TTY (SSH, reverse shell, pseudo-TTY).

**Detection surface**: `sys_enter_write` and `sys_enter_read` on TTY file descriptors. Adversary timing patterns deviate measurably from human baseline distributions across:

- Inter-event delta mean and variance (Welford online, O(1) per update)
- Shannon entropy (base-2) of delta distribution over a sliding window
- Burst-to-pause ratio in byte-count time series

**Active defense mechanism**: Upon anomaly threshold breach (`score ≥ 0.72`, normalized ∈ [0.0, 1.0]), the system injects calibrated exponential-distribution latency into the adversary's TTY file descriptor via a BPF map command consumed by the kernel probe. The system does **not** kill or block the adversary process. It engineers behavioral disclosure. Attribution and termination are explicitly out of scope.

---

## Theoretical Foundation

The jitter injection implements a **Stackelberg defender-leader model**:

- The defender (GHOST-HUNTER) commits first to a signaling policy — a λ schedule drawn from an exponential distribution.
- The adversary observes only the injected delay, not the underlying detection state.
- The optimal adversary response to an unknown λ is to slow down and adopt more human-like timing.
- This behavioral change is itself a high-fidelity confirmation signal.
- λ is updated via Bayesian posterior update on observed inter-event delta residuals, bounded to [0.1, 50.0].

This is derived from Imperfect Information Sequential Game theory: the defender holds private information (the detection state) and employs a mixed strategy (adaptive jitter magnitude) to prevent the adversary from identifying and suppressing the signal.

For an in-depth analysis of the signaling strategy, game-theoretic anomaly detection, and security proofs, refer to the technical white paper below.

---

## White Paper

**[`docs/WP.pdf`](https://github.com/tahakouiyasse/ebpf-impostor-detector/blob/main/docs/WP.pdf)**

The white paper constitutes the formal technical specification for GHOST-HUNTER's detection and signaling model. It covers:

- **Signaling strategy**: formal derivation of the Stackelberg defender-leader equilibrium and the optimal λ schedule under adversary uncertainty.
- **Game-theoretic anomaly detection**: construction of the imperfect information sequential game, payoff matrix analysis, and proof that adaptive jitter dominates static threshold alerting.
- **Statistical model**: specification of the Welford online estimator, Shannon entropy scorer, and the Bayesian posterior update rule for λ — including convergence bounds under non-stationary adversary behaviour.
- **Security proofs**: formal argument that the mixed signaling strategy prevents adversary identification of detection state within the 3–7 interaction cycle window.
- **ABI contract**: layout proofs for `TtyEvent` (64 bytes) and `JitterCommand` (16 bytes) with field-level offset tables and alignment invariants.

> The white paper is the authoritative reference for all design decisions. Where any discrepancy exists between the white paper and the source code, the white paper governs.

---

## Engineering Blueprint

### Workspace Structure

```
ghost-hunter/
├── Cargo.toml                    # Workspace root manifest
├── rust-toolchain.toml           # Toolchain pin: nightly-2026-04-01
│
├── gh-common/                    # LAYER 0: ABI Foundation (no_std compatible)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                # Re-exports only. Zero logic.
│       └── events.rs             # TtyEvent, EventKind, JitterCommand + layout proofs
│
├── gh-probe/                     # LAYER 1: Kernel Space (bpf-unknown-none)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs                # eBPF tracepoints: sys_enter_write, sys_enter_read
│
├── gh-analyzer/                  # LAYER 2: User Space (x86_64-unknown-linux-gnu)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # Tokio runtime init, task orchestration, shutdown
│       ├── loader.rs             # Aya loader, map attach, tracepoint link
│       ├── scoring.rs            # Welford engine, entropy scorer, threshold logic
│       └── bayesian.rs           # λ update, jitter draw, BPF map write, dispatcher
│
└── xtask/                        # LAYER 3: Build Orchestrator (host std)
    ├── Cargo.toml
    └── src/
        └── main.rs               # bpf-linker check → probe compile → artifact copy → analyzer compile
```

### Crate Dependency Graph

```
                    ┌─────────────┐
                    │  gh-common  │  no_std | no deps | ABI layer
                    │  (Layer 0)  │  features: ["user"] for std derives
                    └──────┬──────┘
                           │ path dep
              ┌────────────┼────────────┐
              ▼                         ▼
     ┌────────────────┐       ┌─────────────────────┐
     │   gh-probe     │       │    gh-analyzer       │
     │   (Layer 1)    │       │    (Layer 2)         │
     │  bpf-unknown   │       │  x86_64-linux-gnu    │
     │  -none target  │       │                      │
     │                │       │  aya                 │
     │  aya-ebpf      │       │  tokio (rt-mt)       │
     │  gh-common     │ ──.o──▶  rand (SmallRng)     │
     └────────────────┘       │  tracing             │
                              │  gh-common ["user"]  │
                              └─────────────────────┘
                                         ▲
                              ┌──────────┴──────────┐
                              │       xtask          │
                              │     (Layer 3)        │
                              │  host std only       │
                              │  orchestrates build  │
                              └─────────────────────┘
```

### Layer Responsibilities

| Layer | Crate | Target | Role |
|---|---|---|---|
| 0 | `gh-common` | `no_std` | Canonical ABI types. `TtyEvent` (64 bytes), `JitterCommand` (16 bytes), `EventKind`. All cross-boundary structs defined here exclusively. |
| 1 | `gh-probe` | `bpf-unknown-none` | Zero-alloc eBPF programs hooking `sys_enter_write` / `sys_enter_read`. Emits to `RINGBUF`. Reads `JITTER_CMDS` HashMap to enforce latency. |
| 2 | `gh-analyzer` | `x86_64-unknown-linux-gnu` | Async Tokio daemon. Loads compiled probe via Aya. Polls `AsyncFd<RingBuf>`. Runs Welford scoring, Bayesian λ update, dispatches jitter commands. |
| 3 | `xtask` | host `std` | Cross-compilation orchestrator. Verifies `bpf-linker`, compiles probe for `bpf-unknown-none`, copies artifact, compiles analyzer. |

---

## Defensive Engineering Constraints

All constraints below are absolute. Any violation results in full code rejection.

### Memory Layout & ABI

- All cross-boundary structs carry `#[repr(C)]` and `#[repr(align(8))]` minimum.
- Implicit padding is forbidden. All padding must be explicit named `_pad` fields.
- `usize`, `isize`, raw pointers, and `bool` are forbidden in cross-boundary structs.
- Boundary-crossing enums must be `#[repr(u32)]` or `#[repr(u64)]`.
- All cross-boundary types must originate from `gh-common`. No local redefinition permitted.
- `const_assert_eq!` on `size_of` and `align_of` is mandatory for every cross-boundary struct.

### Zero-Copy Data Transfer

- Kernel-to-user transfer: `BPF_MAP_TYPE_RINGBUF` only. `PerfEventArray` is forbidden.
- eBPF write pattern: `bpf_ringbuf_reserve` → populate in-place → `bpf_ringbuf_submit`. No staging buffers.
- User-space ring poll: `AsyncFd<RingBuf>` via Tokio. Synchronous `poll()` is forbidden in async context.
- All ring buffer structs: `size_of` must be a multiple of 8 bytes.

### eBPF Verifier Safety

- Target: `bpf-unknown-none`. `#![no_std]`. `#![no_main]`. Zero alloc.
- All map accesses bounds-checked. Unchecked indexing is forbidden.
- No unbounded loops. Every loop bound statically provable to the verifier.
- Stack frame ≤ 512 bytes per program. Manually tracked in comments.
- `bpf_probe_read_user` for all user-space pointer reads. Direct user pointer dereference is forbidden.

### Async Runtime

- Runtime: `tokio` with `rt-multi-thread` + `macros`. No other async runtime.
- All blocking I/O: `tokio::task::spawn_blocking`. Blocking on async threads is forbidden.
- TTY jitter writes via dedicated `tokio::sync::mpsc` channel only. Direct write from scoring path is forbidden.
- Worker thread count: explicit configuration. Default detection is forbidden.
- `unwrap()` / `expect()` on `Result`/`Option` are forbidden in production paths.

### Statistical Integrity

- Variance tracking: Welford online algorithm only. Batch recalculation is forbidden.
- Entropy: Shannon base-2 log only.
- λ bounds: [0.1, 50.0]. Out-of-range triggers a structured `WARNING` log, then clamp. Silent clamp is forbidden.
- RNG: `rand::rngs::SmallRng` seeded from `/dev/urandom` once at startup. Per-event re-seed is forbidden.
- Anomaly score must be a normalized float ∈ [0.0, 1.0] before dispatch.

---

## Architectural Decisions

**ADR-001 — RingBuf over PerfEventArray**: `BPF_MAP_TYPE_RINGBUF` provides true zero-copy reserve-in-place semantics, avoids per-CPU buffer management overhead, and eliminates event loss risk during CPU migration.

**ADR-002 — Welford Online for Variance**: Numerically stable for large `n`, O(1) per update. Batch recalculation introduces catastrophic cancellation error for the small-variance, high-mean delta distributions typical of human typing.

**ADR-003 — Fixed-Point λ in `JitterCommand`**: `lambda_scaled` stores `λ × 1000` as `u32`. BPF maps cannot store `f64` reliably across the kernel/user boundary without alignment and endianness risk. Fixed-point `u32` at ×1000 resolution gives λ precision to 0.001, which exceeds statistical requirements.

**ADR-004 — Jitter as Behavioral Disclosure**: The system injects delay. It does not kill, block, or surface an alert to the adversary. Killing the process reveals detection. Jitter forces behavioral disclosure while the adversary believes they retain operational capability — the core game-theoretic advantage of the Stackelberg model.

**ADR-005 — SmallRng Seeded Once**: Single `/dev/urandom` seed at startup. `SmallRng` (xoshiro128++) provides sufficient statistical quality for exponential jitter sampling. Per-event re-seeding would introduce measurable hot-path latency and defeat the purpose of a fast PRNG.

---

## Getting Started

### Prerequisites

- Rust toolchain: `nightly-2026-04-01` (pinned via `rust-toolchain.toml`, applied automatically)
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker) installed and on `$PATH`
- Linux kernel 5.15+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Root or `CAP_BPF` + `CAP_PERFMON` capabilities for probe attachment

### Build

Use `cargo xtask build` to orchestrate probe compilation and analyzer deployment:

```sh
cargo xtask build
```

The xtask pipeline executes in the following order:

1. Verifies `bpf-linker` presence — exits with a structured error on absence.
2. Compiles `gh-probe` for `bpf-unknown-none` with `build-std=core`.
3. Copies the probe artifact to `target/bpf/gh-probe.o`.
4. Compiles `gh-analyzer` for the host target.

The compiled analyzer binary embeds the probe object via `include_bytes!` — no separate probe deployment step is required.

### Run

```sh
sudo ./target/release/gh-analyzer
```

Structured logs are emitted via `tracing-subscriber`. Set `RUST_LOG=ghost_hunter=debug` for diagnostic output.

---

## License

GHOST-HUNTER is licensed under the **GNU General Public License v2.0 (GPLv2)**, in alignment with Linux kernel compatibility requirements for eBPF programs interacting with kernel internals.

See [`LICENSE`](./LICENSE) for the full license text.
