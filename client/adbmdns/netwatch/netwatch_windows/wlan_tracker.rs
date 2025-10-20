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

use anyhow::Error;
use anyhow::Result;
use core::ffi::c_void;
use log::debug;
use log::error;
use log::warn;
use std::ptr;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::NetworkManagement::WiFi;
use windows_sys::Win32::NetworkManagement::WiFi::WlanCloseHandle;
use windows_sys::Win32::NetworkManagement::WiFi::WlanOpenHandle;
use windows_sys::Win32::NetworkManagement::WiFi::WlanRegisterNotification;
use windows_sys::Win32::NetworkManagement::WiFi::L2_NOTIFICATION_DATA;
use windows_sys::Win32::NetworkManagement::WiFi::WLAN_API_VERSION_2_0;
use windows_sys::Win32::NetworkManagement::WiFi::WLAN_CONNECTION_NOTIFICATION_DATA;
use windows_sys::Win32::NetworkManagement::WiFi::WLAN_NOTIFICATION_SOURCE_ACM;
use windows_sys::Win32::NetworkManagement::WiFi::WLAN_REASON_CODE_SUCCESS;

/// A tracker for Windows WLAN (Wi-Fi) connection events.
///
/// This struct uses the Windows Native Wi-Fi (Wlan) API to monitor for successful
/// Wi-Fi connection events. When a successful connection is detected (meaning the
/// device is authenticated and the network is ready to be used), it invokes a
/// user-provided callback.
pub struct WlanTracker {
    handle: HANDLE,
    callback: Box<dyn Fn() + Send + 'static>,
}

impl WlanTracker {
    pub(crate) fn new(callback: impl Fn() + Send + 'static) -> Self {
        Self { handle: ptr::null_mut(), callback: Box::new(callback) }
    }
}

impl WlanTracker {
    /// Starts listening for WLAN connection events.
    ///
    /// This method opens a handle to the WLAN API and registers a notification
    /// callback. The callback will be invoked on a separate thread managed by Windows
    /// when a WLAN event occurs.
    pub fn start(&mut self) -> Result<()> {
        let mut negotiated_version = 0;

        // SAFETY: This is a call to a Windows API function. The handle is checked for errors.
        let ok = unsafe {
            WlanOpenHandle(
                WLAN_API_VERSION_2_0,
                ptr::null_mut(), /* reserved */
                &mut negotiated_version,
                &mut self.handle,
            )
        };

        if ok != ERROR_SUCCESS {
            return Err(Error::msg(format!("WlanOpenHandle failed with error: {}", ok)));
        }

        // Use the `pcallbackcontext` to pass a `self` to `wlan_notification_callback`
        let context: *mut c_void = (self as *mut WlanTracker) as *mut c_void;

        // SAFETY: This is a call to a Windows API function. The handle is valid and the context
        // pointer is a valid pointer to the WlanTracker instance. The WlanTracker is guaranteed
        // to outlive the notification registration.
        let ok = unsafe {
            WlanRegisterNotification(
                self.handle,
                WLAN_NOTIFICATION_SOURCE_ACM,
                TRUE, /* ignore duplicates */
                Some(wlan_notification_callback),
                context,
                ptr::null_mut(), /* reserved */
                ptr::null_mut(), /* previous source */
            )
        };

        if ok != ERROR_SUCCESS {
            self.close_handle();
            return Err(Error::msg(format!("WlanRegisterNotification failed with error: {}", ok)));
        }

        Ok(())
    }

    /// Stops listening for WLAN connection events.
    ///
    /// This method unregisters the notification callback and closes the handle
    /// to the WLAN API, cleaning up all associated resources.
    pub fn stop(&mut self) {
        self.close_handle();
    }

    fn close_handle(&mut self) {
        if self.handle.is_null() {
            return;
        }
        // SAFETY: This is a call to a Windows API function. The handle is valid.
        unsafe {
            WlanCloseHandle(self.handle, ptr::null_mut() /* reserved */)
        };
        self.handle = ptr::null_mut();
    }
}

impl Drop for WlanTracker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Callback function for Windows WLAN notifications.
///
/// This function is registered with `WlanRegisterNotification` and is invoked by the
/// system on a separate thread when a WLAN `WLAN_NOTIFICATION_SOURCE_ACM` event occurs.
///
/// # Arguments
///
/// * `notification` - A pointer to an `L2_NOTIFICATION_DATA` struct containing details
///   about the notification.
/// * `context` - A pointer to user-defined context. In this implementation, it is a
///   pointer to the `WlanTracker` instance that registered the callback.
///
/// # Behavior
///
/// The function checks if the notification is for a successful connection completion
/// (`wlan_notification_acm_connection_complete` with `WLAN_REASON_CODE_SUCCESS`).
/// If it is, it invokes the callback stored within the `WlanTracker` instance.
///
/// # Safety
///
/// This function contains `unsafe` blocks to dereference raw pointers received from
/// the Windows API. It is the responsibility of the caller (`WlanTracker::start`) to
/// ensure that the `context` pointer is a valid, non-null pointer to a `WlanTracker`
/// instance that outlives the notification registration. The `WlanTracker`'s `Drop`
/// implementation ensures the callback is unregistered before the instance is destroyed.
extern "system" fn wlan_notification_callback(
    notification: *mut L2_NOTIFICATION_DATA,
    context: *mut c_void,
) {
    // SAFETY: The context is a pointer to the `WlanTracker` instance passed during
    // `WlanRegisterNotification`. The `WlanTracker`'s lifetime is managed to ensure it
    // outlives the registration, making this cast safe.
    let tracker = match unsafe { (context as *mut WlanTracker).as_ref() } {
        Some(tracker) => tracker,
        None => {
            error!("Received NULL context in wlan_notification_callback.");
            return;
        }
    };

    // SAFETY: The notification pointer is guaranteed to be valid by the Windows API for the
    // duration of the callback.
    let notification = match unsafe { notification.as_ref() } {
        Some(data) => data,
        None => {
            warn!("Received NULL notification data.");
            return;
        }
    };
    debug!("Received {}", get_notification_description(notification));

    let source = notification.NotificationSource;
    let code = notification.NotificationCode as i32;
    if source != WLAN_NOTIFICATION_SOURCE_ACM
        || code != WiFi::wlan_notification_acm_connection_complete
    {
        return;
    }

    if notification.pData.is_null() {
        warn!("Received ACM Connection Complete with null data.");
        return;
    }
    // SAFETY: The pData pointer is guaranteed to be a valid pointer to a
    // WLAN_CONNECTION_NOTIFICATION_DATA struct by the Windows API when the
    // notification source is WLAN_NOTIFICATION_SOURCE_ACM.
    let data = unsafe { &*(notification.pData as *const WLAN_CONNECTION_NOTIFICATION_DATA) };
    let reason = data.wlanReasonCode;
    if reason != WLAN_REASON_CODE_SUCCESS {
        debug!("Received ACM Connection Complete with reason={reason}.");
        return;
    }
    let name = get_string_from_wchar_array(&data.strProfileName);
    debug!("Successfully connected to profile: '{}'. Invoking callback.", name);
    (tracker.callback)();
}

/// Extracts a Rust `String` from a null-terminated array of wide characters (u16).
fn get_string_from_wchar_array(array: &[u16]) -> String {
    let end = array.iter().position(|&c| c == 0).unwrap_or(array.len());
    String::from_utf16_lossy(&array[..end])
}

fn get_notification_description(notification: &L2_NOTIFICATION_DATA) -> String {
    match notification.NotificationSource {
        WLAN_NOTIFICATION_SOURCE_ACM => {
            format!("ACM: {}", acm_code_to_str(notification.NotificationCode as i32))
        }
        source => format!("Other source: {source}"),
    }
}

/// Converts a WLAN ACM notification code to its string representation.
fn acm_code_to_str(code: i32) -> String {
    match code {
        WiFi::wlan_notification_acm_autoconf_enabled => "Autoconf Enabled",
        WiFi::wlan_notification_acm_autoconf_disabled => "Autoconf Disabled",
        WiFi::wlan_notification_acm_background_scan_enabled => "Background Scan Enabled",
        WiFi::wlan_notification_acm_background_scan_disabled => "Background Scan Disabled",
        WiFi::wlan_notification_acm_bss_type_change => "BSS Type Change",
        WiFi::wlan_notification_acm_power_setting_change => "Power Setting Change",
        WiFi::wlan_notification_acm_scan_complete => "Scan Complete",
        WiFi::wlan_notification_acm_scan_fail => "Scan Fail",
        WiFi::wlan_notification_acm_connection_start => "Connection Start",
        WiFi::wlan_notification_acm_connection_complete => "Connection Complete",
        WiFi::wlan_notification_acm_connection_attempt_fail => "Connection Attempt Fail",
        WiFi::wlan_notification_acm_filter_list_change => "Filter List Change",
        WiFi::wlan_notification_acm_interface_arrival => "Interface Arrival",
        WiFi::wlan_notification_acm_interface_removal => "Interface Removal",
        WiFi::wlan_notification_acm_profile_change => "Profile Change",
        WiFi::wlan_notification_acm_profile_name_change => "Profile Name Change",
        WiFi::wlan_notification_acm_profiles_exhausted => "Profiles Exhausted",
        WiFi::wlan_notification_acm_network_not_available => "Network Not Available",
        WiFi::wlan_notification_acm_network_available => "Network Available",
        WiFi::wlan_notification_acm_disconnecting => "Disconnecting",
        WiFi::wlan_notification_acm_disconnected => "Disconnected",
        WiFi::wlan_notification_acm_adhoc_network_state_change => "Adhoc Network State Change",
        WiFi::wlan_notification_acm_profile_unblocked => "Profile Unblocked",
        WiFi::wlan_notification_acm_screen_power_change => "Screen Power Change",
        WiFi::wlan_notification_acm_profile_blocked => "Profile Blocked",
        WiFi::wlan_notification_acm_scan_list_refresh => "Scan List Refresh",
        WiFi::wlan_notification_acm_operational_state_change => "Operational State Change",
        _ => return format!("Unknown Code: {}", code),
    }
    .to_owned()
}
