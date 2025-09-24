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

mod util;

use crate::netwatch::netwatch_linux::util::MsgType;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use libc::RTM_DELLINK;
use libc::RTM_GETLINK;
use libc::RTM_NEWLINK;
use nix::net::if_::IflagsType;
use nix::net::if_::InterfaceFlags;
use nix::sys::socket;
use nix::sys::socket::bind;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::NetlinkAddr;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockProtocol;
use nix::sys::socket::SockType;
use std::collections::HashMap;
use std::fmt;
use std::os::fd::AsRawFd;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use util::IfInfoMsg;
use util::NlMsgHdr;
use zerocopy::FromBytes;

/// The minimal size of NetLink message
///
/// We're only interested in the message [NlMsgHdr] and the [IfInfoMsg] that immediately follows it.
const MIN_MSG_SIZE: usize = size_of::<NlMsgHdr>() + size_of::<IfInfoMsg>();

#[repr(C)]
#[repr(align(4))] // Parsing messages requires them to be are aligned to 4 bytes.
#[derive(Default)]
struct MessageBuffer([u8; MIN_MSG_SIZE]);

/// The result of successfully parsing a NetLink message
///
/// We're only subscribing to Link related messages so we should never get the Unknown value. It's
/// included here for completeness and troubleshooting.
enum ParseResult {
    Link { len: usize, msg_type: MsgType, index: i32, flags: InterfaceFlags },
    Unknown { len: usize, msg_type: MsgType },
}

/// A human-readable representation of a [ParseResult]
impl fmt::Display for ParseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseResult::Link { len, msg_type, index, flags } => {
                write!(
                    f,
                    "{}[{}](index={}, flags={:#x} ({}))",
                    msg_type,
                    len,
                    index,
                    flags.bits(),
                    flags,
                )
            }
            ParseResult::Unknown { len, msg_type } => {
                write!(f, "{}[{}]", msg_type, len,)
            }
        }
    }
}

fn log_change(index: i32, old_flags: InterfaceFlags, new_flags: InterfaceFlags) {
    log::debug!(
        "Change detected on interface {}: flags changed from {:#x} ({}) to {:#x} ({})",
        index,
        old_flags.bits(),
        old_flags,
        new_flags.bits(),
        new_flags,
    );
}

/// Parse a NelLink message buffer
///
/// The buffer should only contain [ParseResult::Link] messages, but we allow for other types which are returned
/// as [ParseResult::Unknown]
fn parse(slice: &[u8]) -> Result<ParseResult> {
    let (header, rest): (&NlMsgHdr, &[u8]) = NlMsgHdr::ref_from_prefix(slice)
        .map_err(|err| anyhow!("Failed to extract NlMsgHdr: {err}"))?;
    let len = header.nlmsg_len as usize;
    match header.nlmsg_type {
        RTM_NEWLINK | RTM_DELLINK | RTM_GETLINK => {
            let (info, _) = IfInfoMsg::ref_from_prefix(rest)
                .map_err(|err| anyhow!("Failed to extract IfInfoMsg: {err}"))?;
            Ok(ParseResult::Link {
                len,
                msg_type: MsgType::new(header.nlmsg_type),
                index: info.ifi_index,
                flags: InterfaceFlags::from_bits_truncate(info.ifi_flags as IflagsType),
            })
        }
        other => Ok(ParseResult::Unknown { len, msg_type: MsgType::new(other) }),
    }
}

fn listen(callback: &(impl Fn() + Send + Sized)) -> Result<()> {
    log::debug!("Creating Netlink socket");
    let fd = socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::empty(),
        Some(SockProtocol::NetlinkRoute),
    )
    .context("Failed to open NetLink socket")?;

    log::debug!("Creating NetlinkAddr");
    let sa = NetlinkAddr::new(0, libc::RTMGRP_LINK as u32);
    bind(fd.as_raw_fd(), &sa).context("Failed to bind NetLinkAddr")?;

    let mut message_buf = MessageBuffer::default();
    let buf = &mut message_buf.0;

    // We keep a shadow state for interface flags in order to dedupe messages that are triggered
    // every few minutes even when no changes are reported.
    // This could happen when wpa_supplicant or any other system does a periodic scan of Wi-Fi.
    // https://g.co/gemini/share/8787d77aec26
    let mut flags_per_interface: HashMap<i32, InterfaceFlags> = HashMap::new();

    loop {
        let len = socket::recv(fd.as_raw_fd(), buf, MsgFlags::empty())
            .context("Failed to read from socket")?;
        log::debug!("Read {} bytes", len);

        let mut offset = 0;
        while offset < len {
            let slice: &[u8] = &buf[offset..len];
            let result = parse(slice)?;

            let len = match result {
                ParseResult::Link { len, index, flags: new_flags, .. } => {
                    log::debug!("Received {}", result);
                    let old_flags = flags_per_interface
                        .get(&index)
                        .copied()
                        .unwrap_or(InterfaceFlags::from_bits_truncate(0));
                    if old_flags != new_flags {
                        log_change(index, old_flags, new_flags);
                        flags_per_interface.insert(index, new_flags);
                        log::debug!("Calling callback.");
                        callback();
                    } else {
                        log::debug!("Flags unchanged.")
                    }
                    len
                }
                ParseResult::Unknown { len, .. } => {
                    log::warn!("Received unexpected RTM message: {}", result);
                    len
                }
            };

            offset += len.next_multiple_of(4);
        }
    }
}

fn listen_forever(callback: impl Fn() + Send + Sized) {
    loop {
        let res = listen(&callback);
        if let Err(e) = res {
            log::debug!("Error in RTMGRP_LINK loop {}", e);
        }

        // Wait a little bit before looping since we will try again to open the AF_ROUTE socket.
        sleep(Duration::from_secs(2));
    }
}

/// Starts a background thread to listen for network changes and
/// sends messages to a channel.
pub fn monitor_network_changes(callback: impl Fn() + Send + 'static) {
    thread::spawn(move || {
        listen_forever(callback);
    });
}
