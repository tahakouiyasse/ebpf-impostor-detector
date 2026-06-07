use anyhow::{Context, Result};
use gh_common::TtyEvent;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

pub const ANOMALY_THRESHOLD: f64 = 0.72;

const ENTROPY_BINS:     usize = 16;
const ENTROPY_RANGE_NS: u64   = 1_000_000;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct WelfordState {
    pub n:                 u64,
    pub mean:              f64,
    pub m2:                f64,
    /// Timestamp of the most recent event for this session.
    /// Zero is the sentinel value meaning "no prior event" (D-003).
    pub last_timestamp_ns: u64,
}

impl WelfordState {
    /// Pure Welford online update — no side effects, no batch recalculation (S1).
    #[inline]
    pub fn update(&mut self, delta_ns: u64) {
        self.n += 1;
        let x      = delta_ns as f64;
        let delta  = x - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = x - self.mean;
        self.m2   += delta * delta2;
    }

    /// Population variance.  Returns `0.0` until at least one sample.
    #[inline]
    pub fn variance(&self) -> f64 {
        if self.n == 0 { 0.0 } else { self.m2 / self.n as f64 }
    }
}

/// Normalised anomaly score in `[0.0, 1.0]` (S5).
#[derive(Debug, Clone, Copy)]
pub struct AnomalyScore(f64);

impl AnomalyScore {
    pub fn new(value: f64) -> Result<Self> {
        anyhow::ensure!(
            value.is_finite() && (0.0..=1.0).contains(&value),
            "AnomalyScore out of range: {} is not in [0.0, 1.0]",
            value
        );
        Ok(Self(value))
    }

    #[inline]
    pub fn value(self) -> f64 { self.0 }
}

pub type SessionMap = HashMap<u64, WelfordState>;

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(
    mut event_rx: mpsc::Receiver<TtyEvent>,
    score_tx:     mpsc::Sender<(u64, AnomalyScore)>,
    token:        CancellationToken,
) -> Result<()> {
    info!("scoring pipeline starting");
    let mut sessions: SessionMap = SessionMap::new();

    loop {
        tokio::select! {
            biased;

            _ = token.cancelled() => {
                info!("scoring: cancellation received, exiting");
                return Ok(());
            }

            maybe_event = event_rx.recv() => {
                match maybe_event {
                    None => {
                        info!("scoring: event channel closed, exiting");
                        return Ok(());
                    }
                    Some(event) => {
                        if let Err(e) = process_event(event, &mut sessions, &score_tx).await {
                            warn!("scoring: process_event error: {:#}", e);
                        }
                    }
                }
            }
        }
    }
}


// ── Private helpers ───────────────────────────────────────────────────────────

async fn process_event(
    event:    TtyEvent,
    sessions: &mut SessionMap,
    score_tx: &mpsc::Sender<(u64, AnomalyScore)>,
) -> Result<()> {
    let key   = event.pid_tgid;
    let state = sessions.entry(key).or_default();

    // D-003: derive delta from canonical TtyEvent timestamp field.
    // `prior == 0` is the sentinel for the first event — skip that delta.
    let prior = state.last_timestamp_ns;
    state.last_timestamp_ns = event.timestamp_ns;

    if prior == 0 {
        // First event for this session: delta undefined, do not update (D-003).
        return Ok(());
    }

    let delta_ns = event.timestamp_ns.saturating_sub(prior);
    state.update(delta_ns);

    // Wait until we have enough samples for a meaningful entropy window.
    if state.n < ENTROPY_BINS as u64 {
        return Ok(());
    }

    let window     = synthetic_window(state, delta_ns);
    let score_raw  = combined_score(state, &window);
    let normalised = score_raw.clamp(0.0, 1.0);
    let score      = AnomalyScore::new(normalised)
        .context("normalised score construction failed")?;

    debug!(pid_tgid = key, score = score.value(), n = state.n, "scoring: event processed");

    if score.value() >= ANOMALY_THRESHOLD && score_tx.send((key, score)).await.is_err() {
    warn!("scoring: score channel closed");
     }

    Ok(())
}

fn combined_score(state: &WelfordState, window: &[u64]) -> f64 {
    0.5 * variance_signal(state) + 0.5 * entropy_score(window)
}

fn variance_signal(state: &WelfordState) -> f64 {
    const REF_VAR: f64 = 500_000.0 * 500_000.0;
    (state.variance() / REF_VAR).clamp(0.0, 1.0)
}

/// Shannon base-2 entropy over a 16-bin histogram (S2).
/// `f64::log2` is used — natural log is FORBIDDEN for the primary signal (S2).
/// Returns a value in `[0.0, 1.0]` normalised by `log2(16) = 4.0` bits.
pub fn entropy_score(window: &[u64]) -> f64 {
    if window.is_empty() { return 0.0; }

    let mut counts = [0u32; ENTROPY_BINS];
    let bin_width  = ENTROPY_RANGE_NS / ENTROPY_BINS as u64;

    for &delta in window {
        let bin = ((delta / bin_width) as usize).min(ENTROPY_BINS - 1);
        counts[bin] += 1;
    }

    let total = window.len() as f64;
    let mut h  = 0.0f64;

    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            h -= p * p.log2();             // log2 mandated by S2
        }
    }

    let h_max = (ENTROPY_BINS as f64).log2();
    (h / h_max).clamp(0.0, 1.0)
}

fn synthetic_window(state: &WelfordState, current_delta: u64) -> [u64; ENTROPY_BINS] {
    let mean  = state.mean.max(0.0) as u64;
    let sigma = state.variance().sqrt().max(0.0) as u64;

    let mut window = [0u64; ENTROPY_BINS];
    for (i, item) in window.iter_mut().enumerate().take(ENTROPY_BINS - 1) {
        let offset = (i as i64 - (ENTROPY_BINS as i64 / 2 - 1)) * sigma as i64 / 2;
        *item = (mean as i64 + offset).max(0) as u64; // <-- On écrit directement dans le pointeur de l'itérateur
    }
    
    window[ENTROPY_BINS - 1] = current_delta;
    window
}