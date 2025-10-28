#[cfg(target_os = "windows")]
pub mod netwatch_windows;

#[cfg(target_os = "macos")]
pub mod netwatch_darwin;

#[cfg(target_os = "linux")]
pub mod netwatch_linux;

#[cfg(target_os = "windows")]
pub use netwatch_windows::monitor_network_changes_native;

#[cfg(target_os = "macos")]
pub use netwatch_darwin::monitor_network_changes_native;

#[cfg(target_os = "linux")]
pub use netwatch_linux::monitor_network_changes_native;

type NetworkMonitorCallback = Box<dyn Fn() + Send + Sync + 'static>;

use log::{debug, error};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

// Depending on the OS, the network monitor can be very verbose, triggering for each route
// modification and interface event. As a precaution, we "debounce" these events, and only
// trigger every DEBOUNCE_CUTOFF seconds.
const DEBOUNCE_CUTOFF: Duration = Duration::from_secs(1);

// To prevent starvation with a system sending network update every second
// we also place a max cap on how much to wait until triggering.
const MAX_DEBOUNCE_DELAY: Duration = Duration::from_secs(5);

fn new_debouncer(callback: NetworkMonitorCallback) -> NetworkMonitorCallback {
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn({
        move || {
            loop {
                // Wait for the first call to arm the timer.
                if let Err(err) = rx.recv() {
                    error!("netwatch debouncer could not recv {err:?}");
                }

                // Keep track of time to trigger on MAX_DEBOUNCE_DELAY
                let start_time = Instant::now();

                // Timer has now been armed, let's wait for either a timeout or a new call.
                loop {
                    match rx.recv_timeout(DEBOUNCE_CUTOFF) {
                        Ok(_) => {
                            // Got another call, reset timer (unless we have reached
                            // max delay(
                            if start_time.elapsed() < MAX_DEBOUNCE_DELAY {
                                debug!("netwatcher, debouncing!");
                                continue;
                            } else {
                                debug!("netwatcher, max debounce delay reached, triggering!");
                                callback();
                                break;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            // Enough time has passed
                            debug!("netwatcher, triggering!");
                            callback();
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            }
        }
    });

    // Return a function that just sends a signal when called
    Box::new(move || {
        let _ = tx.send(());
    })
}

pub fn monitor_network_changes(callback: NetworkMonitorCallback) {
    // We wrap the callback into a debouncer and give the wrapper to the native network monitor.
    let debounced_callback = new_debouncer(callback);
    monitor_network_changes_native(debounced_callback);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::netwatch::{new_debouncer, DEBOUNCE_CUTOFF, MAX_DEBOUNCE_DELAY};

    #[test]
    fn test_debounce_no_fire() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);

        let increment_calls = Box::new(move || {
            calls_clone.fetch_add(1, Ordering::Relaxed);
        });

        let debounced_callback = new_debouncer(increment_calls);
        debounced_callback();
        debounced_callback();
        debounced_callback();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_debounce_fire() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);

        let increment_calls = Box::new(move || {
            calls_clone.fetch_add(1, Ordering::Relaxed);
        });

        let debounced_callback = new_debouncer(increment_calls);
        debounced_callback();
        debounced_callback();
        debounced_callback();

        thread::sleep(DEBOUNCE_CUTOFF + Duration::from_millis(500));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_debounce_multiple_fire() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);

        let increment_calls = Box::new(move || {
            calls_clone.fetch_add(1, Ordering::Relaxed);
        });

        let debounced_callback = new_debouncer(increment_calls);
        debounced_callback();
        debounced_callback();
        debounced_callback();

        thread::sleep(DEBOUNCE_CUTOFF + Duration::from_millis(500));
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        debounced_callback();
        thread::sleep(DEBOUNCE_CUTOFF + Duration::from_millis(500));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_debounce_max_bound() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);

        let increment_calls = Box::new(move || {
            calls_clone.fetch_add(1, Ordering::Relaxed);
        });

        let debounced_callback = new_debouncer(increment_calls);
        for _ in 1..(MAX_DEBOUNCE_DELAY.as_secs() + 2) {
            debounced_callback();
            thread::sleep(DEBOUNCE_CUTOFF);
        }

        assert_ne!(calls.load(Ordering::Relaxed), 0);
    }
}
