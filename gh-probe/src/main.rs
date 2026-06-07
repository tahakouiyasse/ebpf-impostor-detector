#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};
use gh_common::{EventKind, JitterCommand, TtyEvent};

// ---------------------------------------------------------------------------
// Map definitions — all declared with #[map] (constraint V6)
// ---------------------------------------------------------------------------

/// Kernel→user zero-copy event stream (constraints Z1, Z2).
/// Capacity: 4096 * 64 = 262144 bytes — power-of-two multiple of page size.
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(4096 * 64, 0);

/// User→kernel jitter command delivery, keyed by u32 PID.
#[map]
static mut JITTER_CMDS: HashMap<u64, JitterCommand> =
    HashMap::with_max_entries(1024, 0);

// LAST_TS map removed. Delta computation is deferred to user space.
// gh-analyzer/src/scoring.rs computes inter-event deltas from timestamp_ns
// on the ring buffer consumer side. This reduces verifier stack pressure
// and eliminates a map that served no purpose the kernel uniquely requires.

// ---------------------------------------------------------------------------
// Tracepoint entry points
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_write")]
pub fn gh_enter_write(ctx: TracePointContext) -> u32 {
    unsafe { handle_tty_event(&ctx, EventKind::TtyWrite as u32) }.unwrap_or(());
    0u32
}

#[tracepoint(category = "syscalls", name = "sys_enter_read")]
pub fn gh_enter_read(ctx: TracePointContext) -> u32 {
    unsafe { handle_tty_event(&ctx, EventKind::TtyRead as u32) }.unwrap_or(());
    0u32
}

// ---------------------------------------------------------------------------
// Core handler — shared by both tracepoints
// ---------------------------------------------------------------------------

/// Process a single sys_enter_write / sys_enter_read event.
///
/// `#[inline(always)]` mandatory: must not become a separate BPF sub-program.
/// Stack frame merges into caller; verifier sees one contiguous 512 B budget
/// per tracepoint (constraint V4).
///
/// # Safety
/// All user-memory reads via `ctx.read_at` (V7).
/// Map accesses via aya-ebpf API exclusively (V5).
#[inline(always)]
#[allow(static_mut_refs)]
unsafe fn handle_tty_event(ctx: &TracePointContext, kind: u32) -> Result<(), i64> {
    // STACK (merged into caller frame):
    // fd_raw    : 8 B
    // count_raw : 8 B
    // now       : 8 B
    // pid       : 4 B
    // pid_tgid  : 8 B
    // comm      : 16 B  (TASK_COMM_LEN, copied from helper result)
    // ── total  : ~52 B (well within 512 B limit, constraint V4)

    // -----------------------------------------------------------------------
    // 1 — Read fd and count from tracepoint args (V7)
    //
    // sys_enter_write / sys_enter_read tracepoint format:
    //   offset  0 : u64 syscall nr  (unused)
    //   offset  8 : u64 fd
    //   offset 16 : u64 count / len
    // -----------------------------------------------------------------------
    let fd_raw: u64 = ctx.read_at(8).map_err(|_| 0i64)?;
    let count_raw: u64 = ctx.read_at(16).map_err(|_| 0i64)?;

    // -----------------------------------------------------------------------
    // 2 — TTY filter
    //
    // Pass only stdin(0), stdout(1), stderr(2).
    // TTY_FDS whitelist map deferred to future revision per ADR.
    // -----------------------------------------------------------------------
    if fd_raw > 2 {
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // 3 — PID extraction
    // -----------------------------------------------------------------------
    let pid_tgid: u64 = aya_ebpf::helpers::bpf_get_current_pid_tgid();

    // -----------------------------------------------------------------------
    // 4 — Timestamp
    //
    // delta_ns removed from kernel scope. User space computes inter-event
    // deltas from sequential timestamp_ns values on the ring consumer side.
    // -----------------------------------------------------------------------
    let now: u64 = aya_ebpf::helpers::bpf_ktime_get_ns();

    // -----------------------------------------------------------------------
    // 5 — RingBuf reserve → populate in-place → submit  (Z1, Z2)
    // -----------------------------------------------------------------------
    let mut entry = match EVENTS.reserve::<TtyEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring full — drop silently, never block
    };

    let ev = entry.as_mut_ptr();

    (*ev).timestamp_ns = now;
    (*ev).pid_tgid = pid_tgid;
    (*ev).uid_gid = aya_ebpf::helpers::bpf_get_current_uid_gid();
    (*ev).fd = fd_raw as u32;
    (*ev).byte_count = count_raw as u32;
    (*ev).kind_raw = kind;

    // bpf_get_current_comm() takes no arguments in this aya revision.
    // It returns Result<[u8; TASK_COMM_LEN], i32>. On success, copy the
    // bytes into the reserved entry. On failure, leave the field kernel-zeroed
    // (acceptable — comm is best-effort metadata).
    if let Ok(comm) = aya_ebpf::helpers::bpf_get_current_comm() {
        let dst = &mut (*ev).comm;
        let len = if comm.len() < dst.len() { comm.len() } else { dst.len() };
        let mut i = 0usize;
        while i < len {
            dst[i] = comm[i];
            i += 1;
        }
    }
    // _pad is kernel-zeroed on reserve. No write needed.

    entry.submit(0);

    // -----------------------------------------------------------------------
    // 6 — Jitter injection (V3, M5, V8)
    //
    // The maximum loop boundary is strictly restricted to prevent BPF verifier
    // state explosion and avoid kernel soft lockups.
    // Static visibility enforced for the verifier (constraint V3).
    // cmd.active == 1: integer sentinel used instead of bool (constraint M5).
    // -----------------------------------------------------------------------
    if let Some(cmd) = JITTER_CMDS.get(pid_tgid) {
        if cmd.active == 1 {
            // Standard multiplication instead of saturating_mul to avoid __multi3 (128-bit) conversion
            let delay_ns = cmd.delay_us * 1_000u64;
            let deadline: u64 = now.saturating_add(delay_ns);
            
            let mut iters: u32 = 0;
            while iters < 2_000 {
                if aya_ebpf::helpers::bpf_ktime_get_ns() >= deadline {
                    break;
                }
                iters += 1;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Panic handler — required by bpf-unknown-none.
// Unreachable in valid code paths; verifier accepts loop{} here only.
// ---------------------------------------------------------------------------
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}