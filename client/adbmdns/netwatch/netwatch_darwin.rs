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

use crate::netwatch::NetworkMonitorCallback;
use anyhow::anyhow;
use anyhow::Result;
use libc::{
    c_int, c_short, IFF_BROADCAST, IFF_DEBUG, IFF_LOOPBACK, IFF_MULTICAST, IFF_NOARP,
    IFF_NOTRAILERS, IFF_POINTOPOINT, IFF_PROMISC, IFF_RUNNING, IFF_UP, RTM_ADD, RTM_CHANGE,
    RTM_DELADDR, RTM_DELETE, RTM_DELMADDR, RTM_GET, RTM_GET2, RTM_IFINFO, RTM_IFINFO2, RTM_LOCK,
    RTM_LOSING, RTM_MISS, RTM_NEWADDR, RTM_NEWMADDR, RTM_NEWMADDR2, RTM_OLDADD, RTM_OLDDEL,
    RTM_REDIRECT, RTM_RESOLVE,
};
use socket2::Socket;
use std::io::Read;
use std::thread::sleep;
use std::time::Duration;
use std::{fmt, thread};
use zerocopy::{FromBytes, Immutable, KnownLayout};

// We use this struct to peek into what AF_ROUTE is sending. This is the common header
// to all message struct.
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
struct PeekHeader {
    length: u16,
    version: u8,
    msg_type: u8,
}

pub struct IfFlag(pub c_int);
impl fmt::Display for IfFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // List of possible flags (based on <net/if.h>)
        let flag = self.0;

        if flag & IFF_UP != 0 {
            write!(f, "UP ")?;
        };
        if flag & IFF_BROADCAST != 0 {
            write!(f, "BROADCAST ")?;
        };
        if flag & IFF_DEBUG != 0 {
            write!(f, "DEBUG ")?;
        };
        if flag & IFF_LOOPBACK != 0 {
            write!(f, "LOOPBACK ")?;
        };
        if flag & IFF_POINTOPOINT != 0 {
            write!(f, "POINTOPOINT ")?;
        };
        if flag & IFF_NOTRAILERS != 0 {
            write!(f, "NOTRAILERS ")?;
        };
        if flag & IFF_RUNNING != 0 {
            write!(f, "RUNNING ")?;
        };
        if flag & IFF_NOARP != 0 {
            write!(f, "NOARP ")?;
        };
        if flag & IFF_PROMISC != 0 {
            write!(f, "PROMISC ")?;
        };
        if flag & IFF_MULTICAST != 0 {
            write!(f, "MULTICAST ")?;
        };
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
struct IfaMsghdr {
    length: c_short,
    version: u8,
    msg_type: u8,
    addrs: c_int,
    flags: c_int,
    index: c_short,
    // struct if_data, // UNUSED for now
}
impl fmt::Display for IfaMsghdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, length={}", message_type_to_string(self.msg_type), self.length)
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
struct IfMsghdr {
    length: c_short,
    version: u8,
    msg_type: u8,
    addrs: c_int,
    flags: c_int,
    index: c_short,
    metric: c_int,
}

impl fmt::Display for IfMsghdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, length={} flags({:#x})={}",
            message_type_to_string(self.msg_type),
            self.length,
            self.flags,
            IfFlag(self.flags),
        )
    }
}

fn message_type_to_string(msg_type: u8) -> String {
    match msg_type as c_int {
        RTM_ADD => "RTM_ADD".to_string(),
        RTM_DELETE => "RTM_DELETE".to_string(),
        RTM_CHANGE => "RTM_CHANGE".to_string(),
        RTM_GET => "RTM_GET".to_string(),
        RTM_LOSING => "RTM_LOSING".to_string(),
        RTM_REDIRECT => "RTM_REDIRECT".to_string(),
        RTM_MISS => "RTM_MISS".to_string(),
        RTM_LOCK => "RTM_LOCK".to_string(),
        RTM_OLDADD => "RTM_OLDADD".to_string(),
        RTM_OLDDEL => "RTM_OLDDEL".to_string(),
        RTM_RESOLVE => "RTM_RESOLVE".to_string(),
        RTM_NEWADDR => "RTM_NEWADDR".to_string(),
        RTM_DELADDR => "RTM_DELADDR".to_string(),
        RTM_IFINFO => "RTM_IFINFO".to_string(),
        RTM_NEWMADDR => "RTM_NEWMADDR".to_string(),
        RTM_DELMADDR => "RTM_DELMADDR".to_string(),
        RTM_IFINFO2 => "RTM_IFINFO2".to_string(),
        RTM_NEWMADDR2 => "RTM_NEWMADDR2".to_string(),
        RTM_GET2 => "RTM_GET2".to_string(),
        other => format!("Unknown RTM type ({})", other),
    }
}

fn parse<T: fmt::Debug + FromBytes + Immutable + KnownLayout + fmt::Display>(
    buffer: &[u8],
) -> Result<()> {
    let type_name = std::any::type_name::<T>();
    let (msg, _) = T::ref_from_prefix(buffer)
        .map_err(|_err| anyhow!("failed to parse {} message", type_name))?;
    log::info!("Parsed type={} into '{}'", std::any::type_name::<T>(), msg);
    Ok(())
}

fn parse_message(buffer: &[u8]) -> Result<()> {
    let (rt_msg, _) = PeekHeader::ref_from_prefix(buffer)
        .map_err(|_err| anyhow!("failed to parse PeekHeader from routing message"))?;

    // The RTM_IFINFO message uses a if_msghdr	header,	 the  RTM_NEWADDR  and
    // RTM_DELADDR  messages  use  a  ifa_msghdr  header, the RTM_NEWMADDR and
    // RTM_DELMADDR messages use a ifma_msghdr header, the RTM_IFANNOUNCE mes-
    // sage uses a if_announcemsghdr header, and all other  messages  use  the
    // rt_msghdr header.
    match rt_msg.msg_type as c_int {
        RTM_NEWADDR | RTM_DELADDR => {
            parse::<IfaMsghdr>(buffer)?;
        }
        RTM_IFINFO => {
            parse::<IfMsghdr>(buffer)?;
        }
        _ => {
            log::info!("Unhandled message {} ", message_type_to_string(rt_msg.msg_type));
        }
    }
    Ok(())
}

fn listen(callback: &(impl Fn() + Send + Sized)) -> Result<()> {
    log::debug!("Creating AF_ROUTE socket");
    let mut socket = Socket::new(libc::AF_ROUTE.into(), socket2::Type::RAW, None)?;

    loop {
        let mut buffer = [0u8; 65535];
        let bytes_read = socket.read(&mut buffer)?;
        log::debug!("Read {} bytes", bytes_read);
        let _ = parse_message(&buffer[0..bytes_read]);
        callback();
    }
}

fn listen_forever(callback: impl Fn() + Send + Sized) {
    loop {
        let res = listen(&callback);
        if let Err(e) = res {
            log::debug!("Error in AF_ROUTE loop {}", e);
        }

        // Wait a little bit before looping since we will try again to open the AF_ROUTE socket.
        sleep(Duration::from_secs(2));
    }
}

/// Starts a background thread to listen for network changes and
/// sends messages to a channel.
pub fn monitor_network_changes_native(callback: NetworkMonitorCallback) {
    thread::spawn(move || {
        listen_forever(callback);
    });
}
