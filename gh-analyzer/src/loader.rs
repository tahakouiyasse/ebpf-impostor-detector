use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use gh_common::{JitterCommand, TtyEvent};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const PROBE_BYTES: &[u8] =
    include_bytes!("../../target/bpf/gh-probe.o");

/// Handle to the `JITTER_CMDS` map returned to `main.rs` for forwarding
/// to `bayesian.rs`.  Key = pid_tgid (u64), value = JitterCommand.
pub type JitterCmdsMap = HashMap<aya::maps::MapData, u64, JitterCommand>;

/// Entry point called by `main.rs`.
///
/// Loads the eBPF object, attaches both tracepoints, acquires map handles,
/// sends `JitterCmdsMap` to `main.rs` via `map_tx` before entering the
/// poll loop, then polls the ring buffer until cancellation.
pub async fn run(
    event_tx: mpsc::Sender<TtyEvent>,
    token:    CancellationToken,
    map_tx:   oneshot::Sender<JitterCmdsMap>,
) -> Result<()> {
    // ── Load eBPF object ──────────────────────────────────────────────────────
    let mut bpf = Ebpf::load(PROBE_BYTES)
        .context("failed to load gh-probe.o")?;

    // ── Attach tracepoints ────────────────────────────────────────────────────
    attach_tracepoint(&mut bpf, "gh_enter_write", "sys_enter_write")
        .context("failed to attach gh_enter_write")?;
    attach_tracepoint(&mut bpf, "gh_enter_read", "sys_enter_read")
        .context("failed to attach gh_enter_read")?;

    info!("tracepoints attached: gh_enter_write, gh_enter_read");

    // ── Acquire map handles ───────────────────────────────────────────────────
    let ring_buf: RingBuf<_> = RingBuf::try_from(
        bpf.take_map("EVENTS")
            .context("map GHOST_EVENTS not found in probe object")?,
    )
    .context("failed to create RingBuf from GHOST_EVENTS")?;

    // Wrap in AsyncFd for non-blocking readiness notification (Z3).
    // Synchronous poll() on an async thread is FORBIDDEN.
    let async_ring = AsyncFd::new(ring_buf)
        .context("failed to wrap RingBuf in AsyncFd")?;

    let jitter_cmds: JitterCmdsMap = HashMap::try_from(
        bpf.take_map("JITTER_CMDS")
            .context("map JITTER_CMDS not found in probe object")?,
    )
    .context("failed to create HashMap from JITTER_CMDS")?;

    // ── Hand off JitterCmdsMap to main.rs before entering poll loop ───────────
    // main.rs awaits this send before spawning bayesian::run, ensuring
    // the map handle is wired correctly before any jitter writes occur (A3).
    map_tx.send(jitter_cmds)
        .map_err(|_| anyhow::anyhow!(
            "main.rs dropped map_rx before loader could send JitterCmdsMap"
        ))?;

    info!("JitterCmdsMap sent to main.rs — entering ring buffer poll loop");

    // ── Async ring-buffer poll loop (Z3) ──────────────────────────────────────
    poll_ring(async_ring, event_tx, token).await?;

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Attach a single `TracePoint` program by name.
fn attach_tracepoint(bpf: &mut Ebpf, prog_name: &str, event_name: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(prog_name)
        .with_context(|| format!("program '{}' not found in probe object", prog_name))?
        .try_into()
        .with_context(|| format!("program '{}' is not a TracePoint", prog_name))?;

    prog.load()
        .with_context(|| format!("failed to load '{}'", prog_name))?;

    prog.attach("syscalls", event_name)
        .with_context(|| format!("failed to attach '{}' to syscalls/{}", prog_name, event_name))?;

    Ok(())
}

/// Asynchronous ring-buffer consumer using `AsyncFd<RingBuf>` (Z3).
///
/// Pattern:
///   1. Await readability via `AsyncFd::readable()` — no blocking poll.
///   2. Drain all available items from the inner `RingBuf`.
///   3. Call `readable.retain_ready()` to re-arm the readiness guard
///      if items remain, or let it drop to clear the ready state.
async fn poll_ring(
    mut ring: AsyncFd<RingBuf<aya::maps::MapData>>,
    event_tx: mpsc::Sender<TtyEvent>,
    token:    CancellationToken,
) -> Result<()> {
    info!("ring-buffer poll loop starting");

    loop {
        tokio::select! {
            biased;

            _ = token.cancelled() => {
                info!("loader: cancellation received, exiting poll loop");
                return Ok(());
            }

            result = ring.readable_mut() => {
                let mut guard = result
                    .context("AsyncFd::readable() returned error")?;

                // Drain all items currently available in the ring buffer.
                // AsyncFdReadyGuard::get_mut() returns &mut T (tokio API).
                // RingBuf::next() requires &mut self — get_mut() provides it.
                let ring_inner = guard.get_inner_mut();
                let mut forwarded = 0usize;

                while let Some(item) = ring_inner.next() {
                      let bytes: &[u8] = &item;
                      match cast_event(bytes) {
                        Ok(ev) => {
                            if event_tx.send(ev).await.is_err() {
                                warn!("loader: event channel closed, exiting");
                                return Ok(());
                            }
                            forwarded += 1;
                        }
                        Err(e) => {
                            warn!("loader: cast_event failed: {:#}", e);
                        }
                    }
                }

                debug!("loader: drained {} events from ring buffer", forwarded);
                guard.clear_ready();
            }
        }
    }
}

/// Zero-copy cast of a raw kernel byte slice into `TtyEvent` (M1, M2).
///
/// Verifies both size and pointer alignment before constructing the value.
/// Returns an error rather than panicking on violation (A5).
fn cast_event(bytes: &[u8]) -> Result<TtyEvent> {
    let expected = std::mem::size_of::<TtyEvent>();
    anyhow::ensure!(
        bytes.len() == expected,
        "TtyEvent size mismatch: got {} bytes, expected {}",
        bytes.len(),
        expected
    );

    let align = std::mem::align_of::<TtyEvent>();
    anyhow::ensure!(
        (bytes.as_ptr() as usize).is_multiple_of(align),
        "TtyEvent alignment violation: pointer {:p} is not {}-byte aligned",
        bytes.as_ptr(),
        align
    );


    // SAFETY:
    // - Length verified equal to size_of::<TtyEvent>() above.
    // - Pointer alignment verified above.
    // - Kernel writes TtyEvent as a plain byte sequence; TtyEvent is Copy
    //   per gh-common ABI contract (M7), so the read produces a valid owned
    //   value independent of the source buffer lifetime.
    let event = unsafe {
        std::ptr::read_unaligned(bytes.as_ptr() as *const TtyEvent)
    };
    Ok(event)
}