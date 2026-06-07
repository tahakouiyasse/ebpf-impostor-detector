//! Canonical ABI-stable event types shared across the kernel/user boundary.
//! This is the single source of truth for all cross-boundary data structures.
//!
//! DO NOT add logic or impl blocks here — sole exception: TtyEvent::kind()
//! accessor under #[cfg(feature = "user")], which is intrinsic to the type.
use static_assertions::const_assert_eq;

// ── EventKind ────────────────────────────────────────────────────────────────

/// Discriminant for every event emitted by gh-probe.
///
/// `Invalid = 0` is a mandatory sentinel; a zero-initialized map slot is safe
/// to detect and discard on the user-space side.
#[repr(u32)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug, PartialEq, Eq))]
pub enum EventKind {
    Invalid  = 0,
    TtyWrite = 1,
    TtyRead  = 2,
}

// ── TtyEvent ─────────────────────────────────────────────────────────────────

/// A single TTY read/write event, as recorded by the BPF probe.
///
/// Layout: `#[repr(C, align(8))]`, exactly **64 bytes**.
///
/// Field map:
/// ```text
/// offset  0  │ timestamp_ns : u64      (8 B)
/// offset  8  │ pid_tgid     : u64      (8 B)
/// offset 16  │ uid_gid      : u64      (8 B)
/// offset 24  │ fd           : u32      (4 B)
/// offset 28  │ byte_count   : u32      (4 B)
/// offset 32  │ kind_raw     : u32      (4 B)  ← raw EventKind discriminant
/// offset 36  │ comm         : [u8; 16] (16 B) ← process name, NUL-padded
/// offset 52  │ _pad         : [u8; 12] (12 B) ← explicit pad to 64
/// ```
#[repr(C, align(8))]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct TtyEvent {
    /// Monotonic kernel timestamp in nanoseconds (`bpf_ktime_get_ns()`).
    pub timestamp_ns: u64,
    /// `(tgid << 32) | pid` as returned by `bpf_get_current_pid_tgid()`.
    pub pid_tgid: u64,
    /// `(gid << 32) | uid` as returned by `bpf_get_current_uid_gid()`.
    pub uid_gid: u64,
    /// File descriptor involved in the TTY operation.
    pub fd: u32,
    /// Number of bytes transferred.
    pub byte_count: u32,
    /// Raw event discriminant; convert to `EventKind` via `TtyEvent::kind()`.
    pub kind_raw: u32,
    /// Process name (comm), NUL-padded, from `bpf_get_current_comm()`.
    pub comm: [u8; 16],
    /// Explicit padding; must remain zeroed.
    pub _pad: [u8; 12],
}

// Compile-time ABI proof for TtyEvent.
const_assert_eq!(core::mem::size_of::<TtyEvent>(),  64);
const_assert_eq!(core::mem::align_of::<TtyEvent>(),  8);

/// User-space accessor: converts the raw discriminant to a typed `EventKind`.
/// This is the sole impl block permitted in events.rs — pure discriminant
/// conversion, intrinsic to the type, required for ABI safety.
#[cfg(feature = "user")]
impl TtyEvent {
    #[inline]
    pub fn kind(&self) -> EventKind {
        match self.kind_raw {
            1 => EventKind::TtyWrite,
            2 => EventKind::TtyRead,
            _ => EventKind::Invalid,
        }
    }
}
// ── JitterCommand ─────────────────────────────────────────────────────────────

/// A command written into the BPF map by user space to control jitter injection.
///
/// Layout: `#[repr(C, align(8))]`, exactly **16 bytes**.
///
/// Field map:
/// ```text
/// offset  0  │ delay_us      : u64     (8 B)
/// offset  8  │ lambda_scaled : u32     (4 B) ← λ × 1000 fixed-point
/// offset 12  │ active        : u8      (1 B) ← 1 = inject, 0 = passthrough
/// offset 13  │ _pad          : [u8; 3] (3 B)
/// ```
#[repr(C, align(8))]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "user", derive(Debug))]
pub struct JitterCommand {
    /// Base delay to inject, in microseconds.
    pub delay_us: u64,
    /// Poisson λ parameter, scaled by 1 000 (i.e. λ_real = lambda_scaled / 1000.0).
    pub lambda_scaled: u32,
    /// When `1`, the probe injects jitter; when `0`, it passes through unmodified.
    pub active: u8,
    /// Explicit padding; must remain zeroed.
    pub _pad: [u8; 3],
}

// Compile-time ABI proof for JitterCommand.
const_assert_eq!(core::mem::size_of::<JitterCommand>(), 16);
const_assert_eq!(core::mem::align_of::<JitterCommand>(),  8);

#[cfg(feature = "user")]
unsafe impl aya::Pod for JitterCommand {}