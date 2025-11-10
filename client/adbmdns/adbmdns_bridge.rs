/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Crate documentation

//! FFI bindings for the adb mDNS client library.
//!
//! This is a C-compatible bridge to functions to interact with the Rust-based
//! adb mDNS implementation.

use log::error;
use std::ffi::{c_char, CString};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

mod netwatch;
mod zero_config;
use zero_config::ZeroConfig;

mod zero_config_driver;
mod zero_config_driver_channel;

use crate::zero_config::TxtAttributes;
use crate::zero_config::ZeroConfigCommand::Restart;
use zero_config_driver::ZeroConfigDriver;

// These enum and function must be kept in sync with the bridge header file
// TODO: Use bindgen to auto-generate rust from this file.
/// The state of an update event
#[repr(C)]
#[derive(Debug)]
pub enum AdbMdnsUpdate {
    /// A Resource Record was created
    Create = 1,
    /// A Resource Record was updated
    Update = 2,
    /// A Resource Record was deleted
    Delete = 3,
}

/// Struct used to send txt key/value pair over the bridge.
/// Keep in since with the C struct txt_key_value
#[repr(C)]
pub struct TxtKeyValue {
    key: *const u8,
    key_len: u32,
    value: *const u8,
    value_len: u32,
}

// A helper function to handle the CString creation and error.
fn cstring_from_str(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|e| {
        log::warn!("Invalid string '{s}': {e}. Using empty string.");
        // This unwrap is safe because we use a parameter which does not contain a null byte.
        CString::new("").unwrap()
    })
}

/// # Safety
/// The callback provided must:
/// 1. Not retain access to any pointers passed in after the call ends
/// 2. Not mutate any pointed-to data passed in
/// 3. Accept NUL-terminated strings for `instance_name` and `service-type`
/// 4. Accept a buffer of `num_ipv4s` 32-bit values in `ipv4s` (expected to be network order octets)
/// 5. Accept a buffer of bytes in `ipv6s` which is the size of `num_ipv6s` * 16 (expected to be a sequence of sequences of octets, flattened).
pub unsafe extern "C" fn register(cb: EventCallback) {
    let wrapped = Box::new(
        move |event_type: AdbMdnsUpdate,
              instance_name: &str,
              service_type: &str,
              ipv4s: &[Ipv4Addr],
              ipv6s: &[Ipv6Addr],
              port: u16,
              txt_attributes: &TxtAttributes| {
            let instance_str = CString::new(instance_name).unwrap();
            let service_str = CString::new(service_type).unwrap();
            let raw_v4s: Vec<u8> = ipv4s.iter().flat_map(Ipv4Addr::octets).collect();
            // TODO:
            // let raw_v6s: Vec<u128> = ipv6s.iter().map(Ipv6Addr::to_bits).collect();
            // If we can do this, it'd avoid issues with a length from one source and a buffer from collecting another - we'd be getting the length from the vector itself.
            let raw_v6s: Vec<u8> = ipv6s.iter().flat_map(Ipv6Addr::octets).collect();
            debug_assert!(raw_v6s.len() == ipv6s.len() * std::mem::size_of::<u128>());

            // Convert RR::TXT into a bridge format (TxtKeyValue)
            let raw_txt_kvs: Vec<_> = txt_attributes
                .iter()
                .map(|(key, value)| TxtKeyValue {
                    key: key.as_ptr(),
                    key_len: key.len() as u32,
                    value: value.as_ptr(),
                    value_len: value.len() as u32,
                })
                .collect();

            // SAFETY:
            // 1. instance_name and service_type NUL-terminated strings and live across the callback
            // 2. `raw_v4s` is a sequence of `raw_v4s.len()` `u8` * 4s, and lives across the callback.
            // 3. `raw_v6s` should be a sequence of bytes equivalent to the 16 octets per address.
            //    This property dynamically verified by the debug assertion.
            unsafe {
                cb(
                    event_type,
                    instance_str.as_ptr(),
                    service_str.as_ptr(),
                    raw_v4s.len() as _,
                    raw_v4s.as_ptr() as _,
                    ipv6s.len() as _,
                    raw_v6s.as_ptr() as _,
                    port,
                    raw_txt_kvs.len() as u32,
                    raw_txt_kvs.as_ptr(),
                );
            }
        },
    );
    *G_EVENT_CALLBACK.lock().unwrap() = Some(wrapped);
}

// TODO Documentation
fn send_update(
    event_type: AdbMdnsUpdate,
    instance_name: &str,
    service_type: &str,
    ipv4s: &[Ipv4Addr],
    ipv6s: &[Ipv6Addr],
    port: u16,
    txt: &TxtAttributes,
) {
    let guard = G_EVENT_CALLBACK.lock().unwrap();
    if let Some(callback) = &*guard {
        callback(event_type, instance_name, service_type, ipv4s, ipv6s, port, txt);
    }
}

fn run() {
    log::info!("ADB mdns is starting...");

    let zero_config = ZeroConfig::new();

    let (tx, rx) = match zero_config_driver_channel::new() {
        Ok(pair) => pair,
        Err(e) => {
            error!("Unable to create zeroconfig driver channel: {e}");
            return;
        }
    };

    let zero_config_driver = ZeroConfigDriver::new(zero_config, rx);
    netwatch::monitor_network_changes(Box::new(move || {
        if let Err(e) = tx.send(Restart {}) {
            error!("Failed to send restart command on network change: {e}");
        }
    }));

    zero_config_driver.run_forever();
}

// These enum and function must be kept in sync with the bridge header file
// TODO: Use bindgen to auto-generate rust from this file.
/// Defines the signature for the C-compatible logging callback function.
type AdbLoggerCallback =
    extern "C" fn(level: AdbLogLevel, filename: *const c_char, line: u32, message: *const c_char);

// These enum and function must be kept in sync with the bridge header file
// TODO: Use bindgen to auto-generate rust from this file.
/// Defines the signature for the C-compatible event callback function.
type EventCallback = unsafe extern "C" fn(
    event_type: AdbMdnsUpdate,
    instance_name: *const c_char,
    service_type: *const c_char,
    num_ipv4s: u32,
    ipv4s: *const u8,
    num_ipv6s: u32,
    ipv6s: *const u8,
    port: u16,
    num_txt_kvs: u32,
    txt_kvs: *const TxtKeyValue,
);

/// A global, mutable static variable to store the registered log callback.
static G_EVENT_CALLBACK: Mutex<
    Option<
        Box<
            dyn Fn(AdbMdnsUpdate, &str, &str, &[Ipv4Addr], &[Ipv6Addr], u16, &TxtAttributes) + Send,
        >,
    >,
> = Mutex::new(None);

struct AdbLogger {
    logger_callback: AdbLoggerCallback,
}

impl AdbLogger {
    unsafe fn new(callback: AdbLoggerCallback) -> AdbLogger {
        AdbLogger { logger_callback: callback }
    }
}

// These enum and function must be kept in sync with the bridge header file
// TODO: Use bindgen to auto-generate rust from this file.
// Define the enum with a C-compatible memory layout
// Must be kept in sync with the C struct AdbLogLevel in the header file
#[repr(C)]
#[derive(Debug)]
/// TODO
pub enum AdbLogLevel {
    /// The lowest log level, for verbose tracing.
    Trace = 5,
    /// Log level for debugging information.
    Debug = 4,
    /// Log level for general informational messages.
    Info = 3,
    /// Log level for warnings.
    Warn = 2,
    /// The highest log level, for errors.
    Error = 1,
}

impl log::Log for AdbLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let formatted_msg = format!("{}", record.args());
        let c_msg = cstring_from_str(formatted_msg.as_str());

        let filename = record.file().unwrap_or("unknown_filename");
        let c_filename = cstring_from_str(filename);
        let line = record.line().unwrap_or(0);
        let level = match record.level() {
            log::Level::Trace => AdbLogLevel::Trace,
            log::Level::Debug => AdbLogLevel::Debug,
            log::Level::Info => AdbLogLevel::Info,
            log::Level::Warn => AdbLogLevel::Warn,
            log::Level::Error => AdbLogLevel::Error,
        };

        (self.logger_callback)(level, c_filename.as_ptr(), line, c_msg.as_ptr());
    }

    fn flush(&self) {}
}

/// Starts the adbmdns service.
///
/// This function initializes the mDNS bridge and starts a background task
/// to discover and manage ADB devices on the network.
///
/// # Safety
/// The callback provided must:
/// 1. Not retain access to any pointers passed in after the call ends
/// 2. Not mutate any pointed-to data passed in
/// 3. Accept NUL-terminated strings for all const char* parameters
/// 4. Accept a buffer of `num_ipv4s` 32-bit values in `ipv4s` (expected to be network order octets)
/// 5. Accept a buffer of bytes in `ipv6s` which is the size of `num_ipv6s` * 16 (expected to be a sequence of sequences of octets, flattened).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adbmdns_start(
    log_callback: AdbLoggerCallback,
    event_callback: EventCallback,
) {
    // SAFETY: No other thread can be writing to this environment variable.
    unsafe {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    // SAFETY: Assume adb gave us correct logger callback
    unsafe {
        log::set_boxed_logger(Box::new(AdbLogger::new(log_callback)))
            .unwrap_or_else(|e| eprintln!("Failed to set logger: {e}"));
    }
    log::set_max_level(log::LevelFilter::Trace);

    // SAFETY: Assume adb gave us correct logger callback
    unsafe {
        register(event_callback);
    }
    run();
}
