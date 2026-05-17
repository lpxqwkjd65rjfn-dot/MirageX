//! Cheap pre-warm pool. The pool keeps a fixed number of pre-established
//! connections hot in a queue, ready to be consumed by the first user
//! request. Each consumed slot is asynchronously replenished.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

/// Pre-warm pool. Generic over the connection type so it can hold whatever
/// the engine actually uses (TCP, TLS, full Reality stream, etc.).
pub struct Prewarmer<T: Send + 'static> {
    state: Arc<State<T>>,
}

impl<T: Send + 'static> Clone for Prewarmer<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

struct State<T: Send + 'static> {
    target: usize,
    pool: Mutex<Vec<T>>,
    notify: Notify,
}

impl<T: Send + 'static> Prewarmer<T> {
    /// Build a new pool with `target` hot slots.
    #[must_use]
    pub fn new(target: usize) -> Self {
        Self {
            state: Arc::new(State {
                target,
                pool: Mutex::new(Vec::with_capacity(target)),
                notify: Notify::new(),
            }),
        }
    }

    /// Try to take a hot connection out of the pool. Returns `None` when
    /// the pool is empty.
    pub fn take(&self) -> Option<T> {
        let v = self.state.pool.lock().pop();
        if v.is_some() {
            self.state.notify.notify_one();
        }
        v
    }

    /// Spawn a background task that maintains the pool at `target` items
    /// by calling `make()` whenever the pool dips below `target`.
    pub fn spawn<F, Fut>(&self, mut make: F)
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = std::io::Result<T>> + Send + 'static,
    {
        let state = self.state.clone();
        tokio::spawn(async move {
            loop {
                let need = {
                    let pool = state.pool.lock();
                    state.target.saturating_sub(pool.len())
                };
                if need == 0 {
                    state.notify.notified().await;
                    continue;
                }
                for _ in 0..need {
                    let f: Pin<Box<dyn Future<Output = std::io::Result<T>> + Send>> =
                        Box::pin(make());
                    match f.await {
                        Ok(item) => state.pool.lock().push(item),
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        }
                    }
                }
            }
        });
    }
}
