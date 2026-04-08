// rate_limiter.rs — Token-bucket rate limiter wrapping `governor`
use governor::{Quota, RateLimiter as GovLimiter, clock::DefaultClock, state::{InMemoryState, NotKeyed}};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Wraps governor's RateLimiter for easy use.
/// When rate = 0, no limiting is applied.
pub struct RateLimiter {
    limiter: Option<Arc<GovLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    /// - `rate`: connections per second. 0 means unlimited.
    /// - `threads`: concurrent thread count — used as initial burst allowance
    ///   so all threads can fire immediately on startup.
    pub fn new(rate: f64, threads: u32) -> Self {
        if rate <= 0.0 {
            return RateLimiter { limiter: None };
        }

        // Governor works with integer rates.
        let cps = rate.ceil() as u32;
        let cps = cps.max(1);

        // Use burst = max(threads, cps) so the initial wave fills all threads
        let burst = cps.max(threads).max(1);
        let burst_nz = NonZeroU32::new(burst).unwrap();
        let quota = Quota::per_second(NonZeroU32::new(cps).unwrap())
            .allow_burst(burst_nz);
        let limiter = GovLimiter::direct(quota);

        RateLimiter {
            limiter: Some(Arc::new(limiter)),
        }
    }

    /// Wait until a token is available. If no limiter, returns immediately.
    pub async fn acquire(&self) {
        if let Some(ref limiter) = self.limiter {
            limiter.until_ready().await;
        }
    }

    /// Get a clone-friendly Arc reference to this limiter's inner.
    pub fn clone_inner(&self) -> Option<Arc<GovLimiter<NotKeyed, InMemoryState, DefaultClock>>> {
        self.limiter.clone()
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        RateLimiter {
            limiter: self.limiter.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unlimited_rate() {
        let rl = RateLimiter::new(0.0, 100);
        // Should return instantly
        for _ in 0..100 {
            rl.acquire().await;
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let rl = RateLimiter::new(1000.0, 100);
        assert!(rl.limiter.is_some());
    }

    #[tokio::test]
    async fn test_rate_zero_no_limiter() {
        let rl = RateLimiter::new(0.0, 100);
        assert!(rl.limiter.is_none());
    }
}
