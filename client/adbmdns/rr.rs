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

use crate::index_min_pq::CompareAttention;
use std::cmp::{Ordering, PartialEq};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub(crate) struct ServiceTypeWithLocal(pub String);

impl From<String> for ServiceTypeWithLocal {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub(crate) struct FQServiceName {
    pub(crate) instance_name: String,
    pub(crate) service_type: String,
    pub(crate) service_type_with_local: ServiceTypeWithLocal,
    pub(crate) local_domain: String,
}

impl FQServiceName {
    pub(crate) fn new(
        instance_name: String,
        service_type: String,
        domain: String,
    ) -> FQServiceName {
        FQServiceName {
            instance_name,
            service_type_with_local: ServiceTypeWithLocal(format!("{}.{}", service_type, domain)),
            service_type,
            local_domain: domain,
        }
    }

    pub(crate) fn fq_name(&self) -> String {
        format!("{}.{}.{}", self.instance_name, self.service_type, self.local_domain)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum RRPayload {
    A { name: String, addr: Ipv4Addr },
    AAAA { name: String, addr: Ipv6Addr },
    SRV { name: FQServiceName, target: String, port: u16 },
    TXT { name: FQServiceName, attributes: TxtAttributes },
    PTR { name: String, pointer: FQServiceName },
}

impl Hash for RRPayload {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            RRPayload::A { name, addr } => {
                0u8.hash(state);
                name.hash(state);
                addr.hash(state);
            }
            RRPayload::AAAA { name, addr } => {
                1u8.hash(state);
                name.hash(state);
                addr.hash(state);
            }
            RRPayload::SRV { name, .. } => {
                2u8.hash(state);
                name.hash(state);
            }
            RRPayload::TXT { name, .. } => {
                3u8.hash(state);
                name.hash(state);
            }
            RRPayload::PTR { name: _name, pointer } => {
                4u8.hash(state);
                pointer.hash(state);
            }
        }
    }
}

impl PartialEq<Self> for RRPayload {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RRPayload::A { name, addr }, RRPayload::A { name: other_name, addr: other_addr }) => {
                name == other_name && addr == other_addr
            }
            (
                RRPayload::AAAA { name, addr },
                RRPayload::AAAA { name: other_name, addr: other_addr },
            ) => name == other_name && addr == other_addr,
            (RRPayload::SRV { name, .. }, RRPayload::SRV { name: other_name, .. }) => {
                name == other_name
            }
            (RRPayload::TXT { name, .. }, RRPayload::TXT { name: other_name, .. }) => {
                name == other_name
            }
            (
                RRPayload::PTR { name: _name, pointer },
                RRPayload::PTR { name: _other_name, pointer: other_pointer },
            ) => pointer == other_pointer,
            _ => false,
        }
    }
}

// Lifecycle blocks according to mDNS RFC 6462
//  The querier should plan to issue a query at 80% of the record lifetime, and then if no answer
// is received, at 85%, 90%, and 95%.
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RRLifecycle {
    Created,
    Probed80,
    Probed85,
    Probed90,
    Probed95,
}

impl RRLifecycle {
    pub(crate) fn next_ttl_fraction(&self) -> f64 {
        match *self {
            RRLifecycle::Created => 0.80,
            RRLifecycle::Probed80 => 0.85,
            RRLifecycle::Probed85 => 0.90,
            RRLifecycle::Probed90 => 0.95,
            RRLifecycle::Probed95 => 1.00,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RR {
    pub(crate) attention_needed_on: Instant,
    pub(crate) created_on: Instant,
    pub(crate) ttl: Duration,
    pub(crate) next_lifecycle_state: RRLifecycle,
    pub(crate) payload: RRPayload,
}

impl CompareAttention for Rc<RR> {
    fn cmp_attention(&self, other: &Self) -> Ordering {
        self.attention_needed_on.cmp(&other.attention_needed_on)
    }
}
impl RR {
    pub(crate) fn new(now: Instant, ttl: Duration, payload: RRPayload) -> RR {
        let state = RRLifecycle::Created;
        let duration_next_attention = ttl.as_secs_f64() * state.next_ttl_fraction();
        RR {
            created_on: now,
            ttl,
            next_lifecycle_state: state.clone(),
            attention_needed_on: now + Duration::from_secs_f64(duration_next_attention),
            payload,
        }
    }
}

impl Eq for RR {}

impl PartialEq for RR {
    fn eq(&self, other: &Self) -> bool {
        self.payload == other.payload
    }
}

impl Hash for RR {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.payload.hash(state);
    }
}

pub(crate) type TxtAttributes = BTreeMap<String, String>;
