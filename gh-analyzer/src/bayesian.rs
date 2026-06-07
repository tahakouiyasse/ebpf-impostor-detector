use anyhow::{Context, Result};
use gh_common::JitterCommand;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::loader::JitterCmdsMap;
use crate::scoring::AnomalyScore;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Inclusive lower bound for λ (S3).
const LAMBDA_MIN: f64 = 0.1;
/// Inclusive upper bound for λ (S3).
const LAMBDA_MAX: f64 = 50.0;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Bayesian Gamma-distributed posterior over the Poisson rate parameter λ.
///
/// Conjugate prior: λ ~ Gamma(alpha, beta)
///   posterior update on observation x:
///     alpha' = alpha + 1
///     beta'  = beta  + x
///   posterior mean: alpha' / beta'
#[derive(Debug, Clone)]
pub struct LambdaState {
    pub lambda: f64,
    pub alpha:  f64,
    pub beta:   f64,
}

impl LambdaState {
    /// Initialise with a weakly informative prior (alpha=1, beta=1 → λ=1.0).
    pub fn new() -> Self {
        Self { lambda: 1.0, alpha: 1.0, beta: 1.0 }
    }

    /// Bayesian posterior update from an incoming `AnomalyScore`.
    ///
    /// Out-of-range posterior mean MUST emit `tracing::warn!` before
    /// clamping — silent clamp is FORBIDDEN (S3).
    pub fn update(&mut self, score: AnomalyScore) {
        self.alpha += 1.0;
        self.beta  += score.value();

        let raw = self.alpha / self.beta;

        // S3: structured warning mandatory; silent clamp forbidden.
        if raw < LAMBDA_MIN {
            warn!(
                raw_lambda = raw,
                lambda_min = LAMBDA_MIN,
                "bayesian: posterior λ {:.6} is below minimum {:.1}; clamping",
                raw, LAMBDA_MIN
            );
        } else if raw > LAMBDA_MAX {
            warn!(
                raw_lambda = raw,
                lambda_max = LAMBDA_MAX,
                "bayesian: posterior λ {:.6} exceeds maximum {:.1}; clamping",
                raw, LAMBDA_MAX
            );
        }

        self.lambda = raw.clamp(LAMBDA_MIN, LAMBDA_MAX);
    }
}

impl Default for LambdaState {
    fn default() -> Self { Self::new() }
}

// ── Jitter sampling ───────────────────────────────────────────────────────────

/// Draw one exponential sample with rate λ; returns microseconds.
///
/// Exponential inverse-CDF: x = −ln(U) / λ   where U ~ Uniform(0,1).
/// `SmallRng` passed in by reference — per-event re-seed is FORBIDDEN (S4, ADR-005).
pub fn jitter_sample(lambda: f64, rng: &mut SmallRng) -> u64 {
    let u: f64 = 1.0 - rng.gen::<f64>();
    let micros  = (-u.ln() / lambda) * 1_000_000.0;
    micros.clamp(0.0, u64::MAX as f64) as u64
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Async entry point called by `main.rs`.
pub async fn run(
    mut score_rx: mpsc::Receiver<(u64, AnomalyScore)>,
    jitter_map:   JitterCmdsMap,
    token:        CancellationToken,
) -> Result<()> {
    info!("bayesian jitter dispatcher starting");

    // Seed SmallRng once from /dev/urandom at startup (S4, ADR-005).
    // Per-event re-seed is FORBIDDEN.
    let mut rng = SmallRng::from_entropy();

    let mut states: std::collections::HashMap<u64, LambdaState> =
        std::collections::HashMap::new();

    let map = std::sync::Arc::new(std::sync::Mutex::new(jitter_map));

    loop {
        tokio::select! {
            biased;

            _ = token.cancelled() => {
                info!("bayesian: cancellation received, exiting");
                return Ok(());
            }

            maybe_score = score_rx.recv() => {
                match maybe_score {
                    None => {
                        info!("bayesian: score channel closed, exiting");
                        return Ok(());
                    }
                    Some((pid_tgid, score)) => {
                        if let Err(e) = dispatch(
                            pid_tgid,
                            score,
                            &mut states,
                            &mut rng,
                            &map,
                        ).await {
                            warn!("bayesian: dispatch error for pid_tgid {}: {:#}", pid_tgid, e);
                        }
                    }
                }
            }
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

type SharedMap = std::sync::Arc<std::sync::Mutex<JitterCmdsMap>>;

async fn dispatch(
    pid_tgid: u64,
    score:    AnomalyScore,
    states:   &mut std::collections::HashMap<u64, LambdaState>,
    rng:      &mut SmallRng,
    map:      &SharedMap,
) -> Result<()> {
    // ── Bayesian update ───────────────────────────────────────────────────────
    let state = states.entry(pid_tgid).or_default();
    state.update(score);
    let lambda = state.lambda;

    // ── Jitter sample ─────────────────────────────────────────────────────────
    let delay_us = jitter_sample(lambda, rng);

    // ── Fixed-point encoding (ADR-003) ────────────────────────────────────────
    let lambda_scaled = (lambda * 1000.0) as u32;

    // ── Construct JitterCommand — ABI-compliant layout (D-004, M5, M7) ────────
    // pid_tgid is the HashMap key, not a struct field (D-004).
    // active = 1u8 on inject path; bool is FORBIDDEN (M5).
    // _pad zeroed explicitly to satisfy ABI padding contract.
    let cmd = JitterCommand {
        delay_us,
        lambda_scaled,
        active: 1u8,
        _pad: [0u8; 3],
    };

    debug!(
        pid_tgid,
        delay_us,
        lambda,
        lambda_scaled,
        "bayesian: injecting jitter command"
    );

    // ── BPF map write via spawn_blocking (A2) ─────────────────────────────────
    // Blocking map I/O must not execute on an async worker thread (A2).
    let map_clone = std::sync::Arc::clone(map);
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut guard = map_clone
            .lock()
            .map_err(|e| anyhow::anyhow!("jitter_map mutex poisoned: {}", e))?;
        guard
            .insert(pid_tgid, cmd, 0)
            .context("failed to insert JitterCommand into JITTER_CMDS")?;
        Ok(())
    })
    .await
    .context("spawn_blocking panicked on jitter_map insert")?
    .context("jitter_map insert returned error")?;

    Ok(())
}