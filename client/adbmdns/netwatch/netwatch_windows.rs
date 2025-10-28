// Copyright (C) 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod wlan_tracker;

use crate::netwatch::NetworkMonitorCallback;
use log::info;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use wlan_tracker::WlanTracker;

fn listen_forever(callback: impl Fn() + Send + 'static) {
    let mut tracker = WlanTracker::new(callback);
    loop {
        let result = tracker.start();
        match result {
            Ok(_) => {
                info!("Waiting for WLAN events.");
                thread::park()
            }
            Err(err) => {
                log::error!(
                    "Failed to register a WLAN listener: {:?}. Waiting 60 sec to try again.",
                    err
                );
                sleep(Duration::from_secs(60));
                continue;
            }
        }
    }
}

/// Starts a background thread that registers a listener and parks
pub fn monitor_network_changes_native(callback: NetworkMonitorCallback) {
    thread::spawn(move || {
        listen_forever(callback);
    });
}
