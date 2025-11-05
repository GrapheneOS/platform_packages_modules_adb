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

use std::fmt::Display;
use std::fmt::Formatter;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

// A Zerocopy compatible version of libc::nlmsghdr
#[repr(C)]
#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

// A Zerocopy compatible version of libc::ifinfomsg
#[repr(C)]
#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct IfInfoMsg {
    pub ifi_family: u8,
    pub __ifi_pad: u8,
    pub ifi_type: u16,
    pub ifi_index: i32,
    pub ifi_flags: u32,
    pub ifi_change: u32,
}

#[repr(transparent)]
pub struct MsgType(u16);

impl MsgType {
    pub fn new(value: u16) -> MsgType {
        MsgType(value)
    }
}

impl Display for MsgType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", message_type_to_string(self.0))
    }
}

/// Converts a Netlink message type to a human-readable string.
fn message_type_to_string(message_type: u16) -> String {
    match message_type {
        libc::RTM_NEWLINK => "RTM_NEWLINK".to_string(),
        libc::RTM_DELLINK => "RTM_DELLINK".to_string(),
        libc::RTM_GETLINK => "RTM_GETLINK".to_string(),
        libc::RTM_SETLINK => "RTM_SETLINK".to_string(),
        libc::RTM_NEWADDR => "RTM_NEWADDR".to_string(),
        libc::RTM_DELADDR => "RTM_DELADDR".to_string(),
        libc::RTM_GETADDR => "RTM_GETADDR".to_string(),
        libc::RTM_NEWROUTE => "RTM_NEWROUTE".to_string(),
        libc::RTM_DELROUTE => "RTM_DELROUTE".to_string(),
        libc::RTM_GETROUTE => "RTM_GETROUTE".to_string(),
        libc::RTM_NEWNEIGH => "RTM_NEWNEIGH".to_string(),
        libc::RTM_DELNEIGH => "RTM_DELNEIGH".to_string(),
        libc::RTM_GETNEIGH => "RTM_GETNEIGH".to_string(),
        libc::RTM_NEWRULE => "RTM_NEWRULE".to_string(),
        libc::RTM_DELRULE => "RTM_DELRULE".to_string(),
        libc::RTM_GETRULE => "RTM_GETRULE".to_string(),
        libc::RTM_NEWQDISC => "RTM_NEWQDISC".to_string(),
        libc::RTM_DELQDISC => "RTM_DELQDISC".to_string(),
        libc::RTM_GETQDISC => "RTM_GETQDISC".to_string(),
        libc::RTM_NEWTCLASS => "RTM_NEWTCLASS".to_string(),
        libc::RTM_DELTCLASS => "RTM_DELTCLASS".to_string(),
        libc::RTM_GETTCLASS => "RTM_GETTCLASS".to_string(),
        libc::RTM_NEWTFILTER => "RTM_NEWTFILTER".to_string(),
        libc::RTM_DELTFILTER => "RTM_DELTFILTER".to_string(),
        libc::RTM_GETTFILTER => "RTM_GETTFILTER".to_string(),
        libc::RTM_NEWACTION => "RTM_NEWACTION".to_string(),
        libc::RTM_DELACTION => "RTM_DELACTION".to_string(),
        libc::RTM_GETACTION => "RTM_GETACTION".to_string(),
        libc::RTM_NEWPREFIX => "RTM_NEWPREFIX".to_string(),
        libc::RTM_GETMULTICAST => "RTM_GETMULTICAST".to_string(),
        libc::RTM_GETANYCAST => "RTM_GETANYCAST".to_string(),
        libc::RTM_NEWNEIGHTBL => "RTM_NEWNEIGHTBL".to_string(),
        libc::RTM_GETNEIGHTBL => "RTM_GETNEIGHTBL".to_string(),
        libc::RTM_SETNEIGHTBL => "RTM_SETNEIGHTBL".to_string(),
        libc::RTM_NEWNDUSEROPT => "RTM_NEWNDUSEROPT".to_string(),
        libc::RTM_NEWADDRLABEL => "RTM_NEWADDRLABEL".to_string(),
        libc::RTM_DELADDRLABEL => "RTM_DELADDRLABEL".to_string(),
        libc::RTM_GETADDRLABEL => "RTM_GETADDRLABEL".to_string(),
        libc::RTM_GETDCB => "RTM_GETDCB".to_string(),
        libc::RTM_SETDCB => "RTM_SETDCB".to_string(),
        libc::RTM_NEWNETCONF => "RTM_NEWNETCONF".to_string(),
        libc::RTM_GETNETCONF => "RTM_GETNETCONF".to_string(),
        libc::RTM_NEWMDB => "RTM_NEWMDB".to_string(),
        libc::RTM_DELMDB => "RTM_DELMDB".to_string(),
        libc::RTM_GETMDB => "RTM_GETMDB".to_string(),
        libc::RTM_NEWNSID => "RTM_NEWNSID".to_string(),
        libc::RTM_DELNSID => "RTM_DELNSID".to_string(),
        libc::RTM_GETNSID => "RTM_GETNSID".to_string(),
        other => format!("Unknown-{}", other),
    }
}
