#[cfg(target_os = "windows")]
pub mod netwatch_windows;

#[cfg(target_os = "macos")]
pub mod netwatch_darwin;

#[cfg(target_os = "linux")]
pub mod netwatch_linux;

#[cfg(target_os = "windows")]
pub use netwatch_windows::monitor_network_changes;

#[cfg(target_os = "macos")]
pub use netwatch_darwin::monitor_network_changes;

#[cfg(target_os = "linux")]
pub use netwatch_linux::monitor_network_changes;
