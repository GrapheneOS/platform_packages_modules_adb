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
use super::rr::TxtAttributes;
use super::rr::{FQServiceName, RRPayload};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

// The store is where we store all RR we receive from the mDNS port. Entries are deleted based on
// updates to the attention list.
// It is with the store that we take a snapshot of the existing services and can compare it to a
// previous snapshot to detect service creation, deletion, and update.

pub(crate) struct Store {
    pub(super) ptrs: HashSet<FQServiceName>,
    pub(super) srvs: HashMap<String, (String, u16)>,
    pub(super) ipv4s: HashMap<String, HashSet<Ipv4Addr>>,
    pub(super) ipv6s: HashMap<String, HashSet<Ipv6Addr>>,
    pub(super) txts: HashMap<String, TxtAttributes>,
}

impl Store {
    pub(crate) fn clear(&mut self) {
        self.ipv6s.clear();
        self.ipv4s.clear();
        self.txts.clear();
        self.srvs.clear();
        self.ptrs.clear();
    }
}

#[derive(Debug, PartialEq, Default)]
pub(crate) struct InstanceDetails {
    pub(crate) port: u16,
    pub(crate) ipv4s: HashSet<Ipv4Addr>,
    pub(crate) ipv6s: HashSet<Ipv6Addr>,
    pub(crate) txt: TxtAttributes,
}

pub(crate) type Services = HashMap<FQServiceName, InstanceDetails>;

impl Store {
    pub(crate) fn new() -> Store {
        Store {
            ptrs: HashSet::new(),
            srvs: HashMap::new(),
            ipv4s: HashMap::new(),
            ipv6s: HashMap::new(),
            txts: HashMap::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        let mut l = self.ptrs.len() + self.srvs.len() + self.txts.len();

        for set in self.ipv4s.values() {
            l += set.len();
        }

        for set in self.ipv6s.values() {
            l += set.len();
        }
        l
    }

    pub(crate) fn snapshot(&self) -> Services {
        let mut services = Services::new();

        for instance_fq in &self.ptrs {
            let Some((target, port)) = self.srvs.get(&instance_fq.fq_name()) else {
                continue;
            };

            let mut details = InstanceDetails {
                port: *port,
                ipv4s: HashSet::new(),
                ipv6s: HashSet::new(),
                txt: TxtAttributes::new(),
            };

            // Try to add A, and AAAA
            if let Some(ipvs4s) = self.ipv4s.get(target) {
                for e in ipvs4s {
                    details.ipv4s.insert(*e);
                }
            }

            if let Some(ipv6s) = self.ipv6s.get(target) {
                for e in ipv6s {
                    details.ipv6s.insert(*e);
                }
            }

            // If no A or AAAA, don't add it, it is not reachable.
            if details.ipv4s.is_empty() || details.ipv6s.is_empty() {
                continue;
            }

            if let Some(txt) = self.txts.get(&instance_fq.fq_name()) {
                details.txt = txt.clone();
            }

            services.insert(instance_fq.clone(), details);
        }

        services
    }

    pub(crate) fn add(&mut self, rr: &RRPayload) {
        match rr {
            RRPayload::A { name, addr } => {
                let set = self.ipv4s.entry(name.to_owned()).or_default();
                set.insert(*addr);
            }
            RRPayload::AAAA { name, addr } => {
                let set = self.ipv6s.entry(name.to_owned()).or_default();
                set.insert(*addr);
            }
            RRPayload::SRV { name, target, port } => {
                self.srvs.insert(name.fq_name(), (target.clone(), *port));
            }
            RRPayload::TXT { name, attributes } => {
                self.txts.insert(name.fq_name(), attributes.clone());
            }
            RRPayload::PTR { name: _, pointer } => {
                self.ptrs.insert(pointer.clone());
            }
        }
    }

    pub(crate) fn remove(&mut self, rr: &RRPayload) {
        match rr {
            RRPayload::A { name, addr } => {
                if !self.ipv4s.contains_key(name) {
                    return;
                }
                let set = self.ipv4s.entry(name.to_owned()).or_default();
                set.remove(addr);
                if set.is_empty() {
                    self.ipv4s.remove(name);
                }
            }
            RRPayload::AAAA { name, addr } => {
                if !self.ipv6s.contains_key(name) {
                    return;
                }
                let set = self.ipv6s.entry(name.to_owned()).or_default();
                set.remove(addr);
                if set.is_empty() {
                    self.ipv6s.remove(name);
                }
            }
            RRPayload::SRV { name, .. } => {
                self.srvs.remove(&name.fq_name());
            }
            RRPayload::TXT { name, .. } => {
                self.txts.remove(&name.fq_name());
            }
            RRPayload::PTR { name: _, pointer } => {
                self.ptrs.remove(pointer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rr::{FQServiceName, RRPayload, TxtAttributes};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_add() {
        let mut store = super::Store::new();
        let fq_name =
            FQServiceName::new("Instance".to_owned(), "Service".to_owned(), "Local".to_owned());

        store.add(&RRPayload::A { name: "foo".to_owned(), addr: Ipv4Addr::LOCALHOST });
        store.add(&RRPayload::AAAA { name: "foo".to_owned(), addr: Ipv6Addr::LOCALHOST });
        store.add(&RRPayload::SRV { name: fq_name.clone(), target: "bar".to_owned(), port: 0 });
        store.add(&RRPayload::PTR { name: "foo".to_owned(), pointer: fq_name.clone() });
        store.add(&RRPayload::TXT { name: fq_name.clone(), attributes: TxtAttributes::new() });

        assert_eq!(1, store.ipv4s.len());
        assert_eq!(1, store.ipv6s.len());
        assert_eq!(1, store.srvs.len());
        assert_eq!(1, store.ptrs.len());
        assert_eq!(1, store.txts.len());
    }

    #[test]
    fn test_remove() {
        let mut store = super::Store::new();
        let fq_name =
            FQServiceName::new("Instance".to_owned(), "Service".to_owned(), "Local".to_owned());

        store.add(&RRPayload::A { name: "foo".to_owned(), addr: Ipv4Addr::LOCALHOST });
        store.add(&RRPayload::AAAA { name: "foo".to_owned(), addr: Ipv6Addr::LOCALHOST });
        store.add(&RRPayload::SRV { name: fq_name.clone(), target: "bar".to_owned(), port: 0 });
        store.add(&RRPayload::PTR { name: "foo".to_owned(), pointer: fq_name.clone() });
        store.add(&RRPayload::TXT { name: fq_name.clone(), attributes: TxtAttributes::new() });

        store.remove(&RRPayload::A { name: "foo".to_owned(), addr: Ipv4Addr::LOCALHOST });
        store.remove(&RRPayload::AAAA { name: "foo".to_owned(), addr: Ipv6Addr::LOCALHOST });
        store.remove(&RRPayload::SRV { name: fq_name.clone(), target: "bar".to_owned(), port: 0 });
        store.remove(&RRPayload::PTR { name: "foo".to_owned(), pointer: fq_name.clone() });
        store.remove(&RRPayload::TXT { name: fq_name.clone(), attributes: TxtAttributes::new() });

        assert_eq!(0, store.ipv4s.len());
        assert_eq!(0, store.ipv6s.len());
        assert_eq!(0, store.srvs.len());
        assert_eq!(0, store.ptrs.len());
        assert_eq!(0, store.txts.len());
    }
}
