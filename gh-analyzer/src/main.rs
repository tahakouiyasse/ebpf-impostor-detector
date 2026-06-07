use anyhow::{Context, Result};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod loader;
mod scoring;
mod bayesian;

// Worker thread count — explicit value required (A4).
// Default auto-detection via Runtime::new() is FORBIDDEN.
const WORKER_THREADS: usize = 4;

fn main() -> Result<()> {
    // Initialise structured logging; RUST_LOG controls level at runtime.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Build multi-thread runtime with an explicit worker count (A4).
    let runtime = Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
        .context("failed to build Tokio multi-thread runtime")?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    info!("gh-analyzer starting (workers = {})", WORKER_THREADS);

    // Shared cancellation token — broadcast to all child tasks on shutdown.
    let token = CancellationToken::new();

    // Channel: ring-buffer consumer → scoring pipeline (A3).
    let (event_tx, event_rx) = mpsc::channel(1024);

    // Channel: scoring pipeline → jitter dispatcher (A3).
    let (score_tx, score_rx) = mpsc::channel(256);

    // ── Loader setup phase ────────────────────────────────────────────────────
    // `loader::run` returns `JitterCmdsMap` after setup but before the poll
    // loop completes.  We use a oneshot channel so the loader task can hand
    // off the map handle to main before entering its poll loop, without
    // blocking the async executor (A2).
    //
    // Protocol:
    //   1. Loader performs eBPF load + tracepoint attach + map acquisition.
    //   2. Loader sends JitterCmdsMap over `map_tx` then enters poll loop.
    //   3. main.rs awaits `map_rx`, then spawns scoring and bayesian tasks.
    let (map_tx, map_rx) = oneshot::channel();

    // ── Task 1: loader ────────────────────────────────────────────────────────
    let loader_token = token.clone();
    let loader_handle = tokio::spawn(async move {
        if let Err(e) = loader::run(event_tx, loader_token, map_tx).await {
            warn!("loader task exited with error: {:#}", e);
        }
    });

    // Await the JitterCmdsMap handle from the loader setup phase.
    // If the loader fails before sending, map_rx will return an error.
    let jitter_map = map_rx
        .await
        .context("loader failed to send JitterCmdsMap — setup phase error")?;

    info!("loader setup complete, jitter_map handle received");

    // ── Task 2: scoring pipeline ──────────────────────────────────────────────
    let scoring_token = token.clone();
    let scoring_handle = tokio::spawn(async move {
        if let Err(e) = scoring::run(event_rx, score_tx, scoring_token).await {
            warn!("scoring task exited with error: {:#}", e);
        }
    });

    // ── Task 3: jitter dispatcher (Bayesian) ──────────────────────────────────
    let bayesian_token = token.clone();
    let bayesian_handle = tokio::spawn(async move {
        if let Err(e) = bayesian::run(score_rx, jitter_map, bayesian_token).await {
            warn!("bayesian task exited with error: {:#}", e);
        }
    });

    // ── Signal handling: SIGINT + SIGTERM ─────────────────────────────────────
    wait_for_signal().await?;
    info!("shutdown signal received — cancelling all tasks");
    token.cancel();

    // ── Structured shutdown: join all tasks ───────────────────────────────────
    let (r1, r2, r3) = tokio::join!(loader_handle, scoring_handle, bayesian_handle);
    r1.context("loader task panicked")?;
    r2.context("scoring task panicked")?;
    r3.context("bayesian task panicked")?;

    info!("gh-analyzer shutdown complete");
    Ok(())
}

/// Resolves on the first of SIGINT or SIGTERM.
/// Both signals are handled uniformly — no distinction in shutdown path.
async fn wait_for_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint =
        signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;

    tokio::select! {
        _ = sigint.recv()  => info!("SIGINT received"),
        _ = sigterm.recv() => info!("SIGTERM received"),
    }
    Ok(())
}