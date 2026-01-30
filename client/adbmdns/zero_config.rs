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
use crate::index_min_pq::IndexMinPQ;
use crate::rr::{FQServiceName, RRLifecycle, RRPayload, ServiceTypeWithLocal, TxtAttributes, RR};
use crate::store::{Services, Store};
use anyhow::{anyhow, Result};
use log::debug;
use simple_dns::rdata::RData::{A, AAAA, PTR, SRV, TXT};
use simple_dns::{Name, ResourceRecord, QTYPE};
use std::cmp::PartialEq;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::mem::take;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};
use ZeroConfigCommand::DnsQuery;

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum ZeroConfigCommand {
    DnsQuery {
        query: String,
        qtype: simple_dns::QTYPE,
        qclass: simple_dns::QCLASS,
    },
    CreateService {
        instance_name: String,
        service_type: String,
        ipv4s: HashSet<Ipv4Addr>,
        ipv6s: HashSet<Ipv6Addr>,
        port: u16,
        txt: TxtAttributes,
    },
    UpdateService {
        instance_name: String,
        service_type: String,
        ipv4s: HashSet<Ipv4Addr>,
        ipv6s: HashSet<Ipv6Addr>,
        port: u16,
        txt: TxtAttributes,
    },
    DeleteService {
        instance_name: String,
        service_type: String,
    },
    Restart {},
}

pub(crate) struct ZeroConfig {
    commands: Vec<ZeroConfigCommand>,

    // The list of tracked services. e.g.: _adb-tls-connect._tcp
    tracked_services: HashMap<ServiceTypeWithLocal, TrackedService>,

    attention_list: IndexMinPQ<Rc<RR>>,

    store: Store,

    now: Instant,

    last_snap_shot: Services,
}

impl Display for FQServiceName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.instance_name, self.service_type, self.local_domain)
    }
}

impl<'a> TryFrom<&Name<'a>> for FQServiceName {
    type Error = anyhow::Error;

    fn try_from(name: &Name<'a>) -> Result<FQServiceName> {
        let parts = name.get_labels();
        if parts.len() != 4 {
            return Err(anyhow!("name does not have 4 parts: {name}"));
        }

        let instance_name = parts[0].to_string();
        let service = parts[1].to_string();
        let protocol = parts[2].to_string();
        let service_type = format!("{service}.{protocol}");
        let domain = parts[3].to_string();

        Ok(FQServiceName::new(instance_name, service_type, domain))
    }
}

const TLS_CONNECT_SERVICE: &str = "_adb-tls-connect._tcp";
const TLS_PAIRING_SERVICE: &str = "_adb-tls-pairing._tcp";
const TCP_CONNECT_SERVICE: &str = "_adb._tcp";

#[derive(Debug, Clone)]
struct TrackedService {
    service_name: String,
    local: String,
}

impl From<TrackedService> for ServiceTypeWithLocal {
    fn from(val: TrackedService) -> Self {
        ServiceTypeWithLocal(format!("{}.{}", val.service_name, val.local))
    }
}

impl ZeroConfig {
    pub(crate) fn new() -> ZeroConfig {
        let mut zero_config = ZeroConfig {
            commands: Vec::new(),
            tracked_services: HashMap::new(),
            attention_list: IndexMinPQ::new(),
            store: Store::new(),
            now: Instant::now(),
            last_snap_shot: HashMap::new(),
        };
        zero_config.track_service(TLS_CONNECT_SERVICE.to_owned());
        zero_config.track_service(TLS_PAIRING_SERVICE.to_owned());
        zero_config.track_service(TCP_CONNECT_SERVICE.to_owned());
        zero_config
    }

    pub fn on_start(&mut self) -> Vec<ZeroConfigCommand> {
        let mut commands = Vec::new();
        for service in self.tracked_services.keys() {
            let ServiceTypeWithLocal(service_type_with_local_string) = service;
            commands.push(ZeroConfigCommand::DnsQuery {
                query: service_type_with_local_string.clone(),
                qtype: simple_dns::QTYPE::ANY,
                qclass: simple_dns::QCLASS::ANY,
            });
        }
        commands
    }

    // See RFC 6762,  10.3. Cache Flush on Topology change. ZeroConfig cache is flushed
    // when it is stopped (likely from a netwatch event).
    pub fn on_stop(&mut self) -> Vec<ZeroConfigCommand> {
        self.attention_list.clear();
        self.store.clear();
        let (commands, _) = self.tick();
        commands
    }

    pub fn track_service(&mut self, service: String) {
        let tracked_service =
            TrackedService { service_name: service.to_owned(), local: "local".to_owned() };
        let service_type_with_local = tracked_service.clone().into();
        self.tracked_services.insert(service_type_with_local, tracked_service);
    }

    fn add_rr(&mut self, rr: Rc<RR>) {
        debug!("Processing RR: {:?}", rr.payload);
        self.attention_list.push(rr.clone());

        // Also add to store
        self.store.add(&rr.payload);
    }

    fn process_records(&mut self, records: &Vec<ResourceRecord>) {
        for record in records {
            let rr = match &record.rdata {
                PTR(ptr) => {
                    let pointer = match FQServiceName::try_from(&ptr.0) {
                        Ok(s) => s,
                        Err(_) => {
                            continue;
                        }
                    };

                    let service_type_with_local = &pointer.service_type_with_local;
                    if !self.tracked_services.contains_key(service_type_with_local) {
                        continue;
                    }
                    Some(RR::new(
                        self.now,
                        Duration::from_secs(record.ttl as u64),
                        RRPayload::PTR { name: record.name.to_string(), pointer },
                    ))
                }
                SRV(srv) => {
                    let name = match FQServiceName::try_from(&record.name) {
                        Ok(s) => s,
                        Err(_) => {
                            continue;
                        }
                    };

                    if !self.tracked_services.contains_key(&name.service_type_with_local) {
                        continue;
                    }
                    Some(RR::new(
                        self.now,
                        Duration::from_secs(record.ttl as u64),
                        RRPayload::SRV { name, target: srv.target.to_string(), port: srv.port },
                    ))
                }
                A(ip) => Some(RR::new(
                    self.now,
                    Duration::from_secs(record.ttl as u64),
                    RRPayload::A { name: record.name.to_string(), addr: ip.address.into() },
                )),
                AAAA(ip) => Some(RR::new(
                    self.now,
                    Duration::from_secs(record.ttl as u64),
                    RRPayload::AAAA { name: record.name.to_string(), addr: ip.address.into() },
                )),
                TXT(txt_rdata) => {
                    // The dns_parser crate provides an iterator for TXT records
                    let mut attributes: TxtAttributes = BTreeMap::new();
                    for (key, option) in txt_rdata.attributes() {
                        let value = option.unwrap_or("".to_string());
                        attributes.insert(key, value);
                    }

                    let name = match FQServiceName::try_from(&record.name) {
                        Ok(s) => s,
                        Err(_) => {
                            continue;
                        }
                    };

                    if !self.tracked_services.contains_key(&name.service_type_with_local) {
                        continue;
                    }
                    Some(RR::new(
                        self.now,
                        Duration::from_secs(record.ttl as u64),
                        RRPayload::TXT { name, attributes },
                    ))
                }
                _ => None,
            };

            if let Some(rr) = rr {
                self.add_rr(Rc::new(rr));
            }
        }
    }

    fn create_diff_commands(&mut self) {
        let snapshot = self.store.snapshot();

        for (service, details) in &snapshot {
            if !self.last_snap_shot.contains_key(service) {
                // Detect new services
                self.commands.push(ZeroConfigCommand::CreateService {
                    instance_name: service.instance_name.clone(),
                    service_type: service.service_type.clone(),
                    ipv4s: details.ipv4s.clone(),
                    ipv6s: details.ipv6s.clone(),
                    port: details.port,
                    txt: details.txt.clone(),
                });
            } else {
                // Detect updated services
                let other = self
                    .last_snap_shot
                    .get(service)
                    .expect("No matching service in last snapshot. Cannot diff");
                if details != other {
                    self.commands.push(ZeroConfigCommand::UpdateService {
                        instance_name: service.instance_name.clone(),
                        service_type: service.service_type.clone(),
                        ipv4s: details.ipv4s.clone(),
                        ipv6s: details.ipv6s.clone(),
                        port: details.port,
                        txt: details.txt.clone(),
                    });
                }
            }
        }

        // Detect deleted services
        for service in self.last_snap_shot.keys() {
            if !snapshot.contains_key(service) {
                self.commands.push(ZeroConfigCommand::DeleteService {
                    instance_name: service.instance_name.clone(),
                    service_type: service.service_type.clone(),
                });
            }
        }

        self.last_snap_shot = snapshot;
    }

    pub fn set_time(&mut self, now: Instant) {
        self.now = now;
    }

    pub fn push_records(
        &mut self,
        answers: Vec<ResourceRecord>,
        additional: Vec<ResourceRecord>,
        nameserver: Vec<ResourceRecord>,
    ) {
        // Combine all records from the mDNS packet into a single list for processing.
        // This allows finding related records (e.g., PTR, SRV, A/AAAA) that may be in
        // different sections of the packet.
        let all_records: Vec<_> = answers.into_iter().chain(additional).chain(nameserver).collect();

        if all_records.is_empty() {
            return;
        }

        debug!("Processing {} records from mDNS packet", all_records.len());
        self.process_records(&all_records);
    }

    pub fn tick(&mut self) -> (Vec<ZeroConfigCommand>, Duration) {
        // Build a list of all the rr that need attention or expiration
        while let Some(attention_element) = self.attention_list.peek() {
            if attention_element.attention_needed_on > self.now {
                break;
            }

            let element = self.attention_list.pop().expect("popping from empty index min pq");

            // Where are we in the rr lifecycle?
            let lifecycle_fraction =
                (self.now - element.created_on).as_secs_f64() / element.ttl.as_secs_f64();

            // Is the RR expired?
            if !(0.0..1.0).contains(&lifecycle_fraction) {
                self.store.remove(&element.payload);
                continue;
            }

            // Need probing
            let next_lifecycle_state = if lifecycle_fraction >= 0.95 {
                RRLifecycle::Probed95
            } else if lifecycle_fraction >= 0.90 {
                RRLifecycle::Probed90
            } else if lifecycle_fraction >= 0.85 {
                RRLifecycle::Probed85
            } else if lifecycle_fraction >= 0.80 {
                RRLifecycle::Probed80
            } else {
                debug!("RR in PQ below threshold: {element:?}");
                // Something very wrong has happened. This should never happen.
                self.store.remove(&element.payload);
                continue;
            };

            // Calculate next attention time, issue query, and re-insert into attention priority queue.
            let mut rr = (*element).clone();
            rr.attention_needed_on = element.created_on
                + Duration::from_secs_f64(
                    element.ttl.as_secs_f64() * next_lifecycle_state.next_ttl_fraction(),
                );
            rr.lifecycle_state = next_lifecycle_state;
            self.create_query_for_record(&rr);
            self.attention_list.push(Rc::new(rr));
        }

        debug!("Store size={}, attention size={}", self.store.len(), self.attention_list.len());

        // Generate a diff and send commands to create/delete/update
        self.create_diff_commands();

        (take(self.commands.as_mut()), self.calculate_next_attention_duration())
    }

    fn calculate_next_attention_duration(&self) -> Duration {
        // Calculate next attention
        let mut duration = Duration::from_secs(60);
        if let Some(rr) = self.attention_list.peek() {
            duration = rr.attention_needed_on.saturating_duration_since(self.now);
            debug!("Next attention in {}ms for {rr:?}", duration.as_millis());
        }
        duration
    }

    fn create_query_for_record(&mut self, rr: &RR) {
        let query = match &rr.payload {
            RRPayload::A { name, .. } => name.to_owned(),
            RRPayload::AAAA { name, .. } => name.to_owned(),
            RRPayload::SRV { name, .. } => name.fq_name(),
            RRPayload::TXT { name, .. } => name.fq_name(),
            RRPayload::PTR { name, .. } => name.to_owned(),
        };

        let qtype = match &rr.payload {
            RRPayload::A { .. } => QTYPE::TYPE(simple_dns::TYPE::A),
            RRPayload::AAAA { .. } => QTYPE::TYPE(simple_dns::TYPE::AAAA),
            RRPayload::SRV { .. } => QTYPE::TYPE(simple_dns::TYPE::SRV),
            RRPayload::TXT { .. } => QTYPE::TYPE(simple_dns::TYPE::TXT),
            RRPayload::PTR { .. } => QTYPE::TYPE(simple_dns::TYPE::PTR),
        };

        self.commands.push(DnsQuery { query, qtype, qclass: simple_dns::QCLASS::ANY });
    }
}

#[cfg(test)]
mod tests {
    use super::{FQServiceName, ServiceTypeWithLocal, TxtAttributes, TCP_CONNECT_SERVICE};
    use super::{ZeroConfig, ZeroConfigCommand, TLS_CONNECT_SERVICE};
    use crate::rr::RRLifecycle;
    use log::debug;
    use simple_dns::rdata::RData::SRV;
    use simple_dns::rdata::{RData, A, TXT};
    use simple_dns::{Name, ResourceRecord, CLASS};
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    const DEFAULT_SHORT_TTL: f64 = 120.0;
    const DEFAULT_LONG_TTL: f64 = 4500.0;

    fn a(name: &str, ip: Ipv4Addr) -> ResourceRecord {
        ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            DEFAULT_SHORT_TTL as u32,
            RData::A(A::from(ip)),
        )
    }

    fn aaaa(name: &str, ip: Ipv6Addr) -> ResourceRecord {
        ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            DEFAULT_SHORT_TTL as u32,
            RData::AAAA(simple_dns::rdata::AAAA::from(ip)),
        )
    }

    fn srv<'a>(name: &'a str, target: &'a str, port: u16) -> ResourceRecord<'a> {
        let srv_rdata = simple_dns::rdata::SRV {
            priority: 10,
            weight: 50,
            port,
            target: Name::new_unchecked(target),
        };
        ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            DEFAULT_SHORT_TTL as u32,
            SRV(srv_rdata),
        )
    }

    fn txt<'a>(name: &'a str, attributes: &'a TxtAttributes) -> ResourceRecord<'a> {
        let mut txt = TXT::new();
        for (key, value) in attributes {
            let string = format!("{}={}", key, value);
            // The TXT record borrows the string data. For dynamically created strings in a test,
            // we can leak the string to get a 'static reference that will live for the duration
            // of the test, satisfying the borrow checker.
            let static_string: &'static str = Box::leak(string.into_boxed_str());
            let _ = txt.add_string(static_string);
        }

        ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            DEFAULT_SHORT_TTL as u32,
            RData::TXT(txt),
        )
    }

    fn ptr_with_ttl<'a>(
        name: &'a ServiceTypeWithLocal,
        domain: &'a str,
        ttl: u32,
    ) -> ResourceRecord<'a> {
        let rdata_struct: simple_dns::rdata::PTR =
            simple_dns::rdata::PTR(Name::new_unchecked(domain));

        let rdata_enum = RData::PTR(rdata_struct);

        ResourceRecord::new(Name::new_unchecked(&name.0), CLASS::IN, ttl, rdata_enum)
    }

    fn ptr<'a>(name: &'a ServiceTypeWithLocal, domain: &'a str) -> ResourceRecord<'a> {
        ptr_with_ttl(name, domain, DEFAULT_LONG_TTL as u32)
    }

    #[test]
    fn test_update_nothing_discovered() {
        let mut zero_conf = ZeroConfig::new();
        let service =
            FQServiceName::new("my_prt".to_string(), "_srv._tcp".to_string(), "local".to_string());
        let fq_service = service.fq_name();
        let server = "my_target";
        let port = 5555;
        let txt_attributes = TxtAttributes::new();

        let answers = vec![
            txt(&fq_service, &txt_attributes),
            a("_srv.local", Ipv4Addr::new(127, 0, 0, 1)),
            aaaa("_srv.local", Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            srv(&fq_service, server, port),
            ptr_with_ttl(&service.service_type_with_local, &fq_service, DEFAULT_SHORT_TTL as u32),
        ];

        zero_conf.set_time(Instant::now());
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);
    }

    #[test]
    fn test_update_service_records() {
        let mut zero_conf = ZeroConfig::new();

        // Let's create a service
        let service_port = 5555u16;
        let service = FQServiceName::new(
            "InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let fq_service = service.fq_name();
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let target = "MyTarget.local";
        let mut txt_attributes = TxtAttributes::new();
        txt_attributes.insert("name".to_owned(), "fab".to_owned());

        let answers = vec![
            txt(&fq_service, &txt_attributes),
            a(target, ipv4),
            aaaa(target, ipv6),
            srv(&fq_service, target, service_port),
            ptr(&service.service_type_with_local, &fq_service),
        ];

        let mut now = Instant::now();
        zero_conf.set_time(now);
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        let create_cmd = cmds.first().unwrap();
        match create_cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port,
                txt,
            } => {
                assert_eq!(service.instance_name, *instance_name);
                assert_eq!(service.service_type, *service_type);
                assert_eq!(*port, service_port);
                assert_eq!(*txt, txt_attributes);
                assert!(ipv4s.contains(&ipv4));
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {create_cmd:?}");
            }
        }

        now += Duration::from_secs(2);
        zero_conf.set_time(now);
        let mut txt_attributes_update = TxtAttributes::new();
        txt_attributes_update.insert("name".to_owned(), "fab2".to_owned());
        let txt_updates = vec![txt(&fq_service, &txt_attributes_update)];
        zero_conf.push_records(txt_updates, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        let update_cmd = cmds.first().unwrap();
        match update_cmd {
            ZeroConfigCommand::UpdateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port,
                txt,
            } => {
                assert_eq!(service.instance_name, *instance_name);
                assert_eq!(service.service_type, *service_type);
                assert_eq!(*txt, txt_attributes_update);
                assert_eq!(*port, service_port);
                assert!(ipv4s.contains(&ipv4));
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {update_cmd:?}");
            }
        }

        now += Duration::from_secs(2);
        zero_conf.set_time(now);
        let new_port = 6666;
        let txt_updates = vec![srv(&fq_service, target, new_port)];
        zero_conf.push_records(txt_updates, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::UpdateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port,
                txt,
            } => {
                assert_eq!(service.instance_name, *instance_name);
                assert_eq!(service.service_type, *service_type);
                assert_eq!(*port, new_port);
                assert_eq!(*txt, txt_attributes_update);
                assert!(ipv4s.contains(&ipv4));
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        }
    }

    #[test]
    fn test_create_service() {
        let mut zero_conf = ZeroConfig::new();
        let port = 5555u16;
        let service = FQServiceName::new(
            "InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let fq_service = service.fq_name();

        let mut expected_ipv4s = HashSet::new();
        expected_ipv4s.insert(Ipv4Addr::new(127, 0, 0, 1));

        let mut expected_ipv6s = HashSet::new();
        expected_ipv6s.insert(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

        let target = "MyTarget.local";

        let mut answers = Vec::new();

        let mut txt_attributes = TxtAttributes::new();
        txt_attributes.insert("key".to_owned(), "value".to_owned());
        txt_attributes.insert("key2".to_owned(), "value2".to_owned());

        answers.push(txt(&fq_service, &txt_attributes));
        for addr in &expected_ipv4s {
            answers.push(a(target, *addr));
        }
        for addr in &expected_ipv6s {
            answers.push(aaaa(target, *addr));
        }
        answers.push(srv(&fq_service, target, port));
        answers.push(ptr_with_ttl(
            &service.service_type_with_local,
            &fq_service,
            DEFAULT_SHORT_TTL as u32,
        ));

        zero_conf.set_time(Instant::now());
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_ne!(cmds.len(), 0);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port: p,
                txt,
            } => {
                assert_eq!(instance_name, &service.instance_name);
                assert_eq!(service_type, &service.service_type);
                assert_eq!(port, *p);
                assert_eq!(*ipv4s, expected_ipv4s);
                assert_eq!(*ipv6s, expected_ipv6s);
                assert_eq!(zero_conf.commands.len(), 0);
                assert_eq!(txt, &txt_attributes)
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        };
    }

    #[test]
    fn test_ignored_delete() {
        let mut zero_conf = ZeroConfig::new();
        let service = FQServiceName::new(
            "my_instance".to_string(),
            "chromecast._tcp".to_string(),
            "local".to_string(),
        );
        let fq_service = service.fq_name();
        let answers = vec![ptr_with_ttl(&service.service_type_with_local, &fq_service, 0)];
        zero_conf.set_time(Instant::now());
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);
    }

    #[test]
    fn test_delete() {
        let mut zero_conf = ZeroConfig::new();

        // Let's create a service
        let port = 5555u16;
        let service = FQServiceName::new(
            "InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let fq_service = service.fq_name();
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let target = "MyTarget.local";
        let txt_attributes = TxtAttributes::new();

        let answers = vec![
            txt(&fq_service, &txt_attributes),
            a(target, ipv4),
            aaaa(target, ipv6),
            srv(&fq_service, target, port),
            ptr(&service.service_type_with_local, &fq_service),
        ];

        let now = Instant::now();
        zero_conf.set_time(now);
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        let ZeroConfigCommand::CreateService { .. } = cmds.first().unwrap() else {
            panic!("Unexpected command {:?}", cmds.first().unwrap());
        };

        // Now let's expire the service
        let answers = vec![ptr_with_ttl(&service.service_type_with_local, &fq_service, 0)];
        zero_conf.set_time(now + Duration::from_secs(1));
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_ne!(cmds.len(), 0);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(service.instance_name, *instance_name);
                assert_eq!(service.service_type, *service_type);
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        }
    }

    #[test]
    fn test_expiration() {
        let mut zero_conf = ZeroConfig::new();

        // Let's create a service
        let port = 5555u16;
        let service = FQServiceName::new(
            "InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let fq_service = service.fq_name();
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let target = "MyTarget.local";
        let txt_attributes = TxtAttributes::new();

        let answers = vec![
            txt(&fq_service, &txt_attributes),
            a(target, ipv4),
            aaaa(target, ipv6),
            srv(&fq_service, target, port),
            ptr(&service.service_type_with_local, &fq_service),
        ];

        // Add the service with a first update
        let epoch = Instant::now();
        zero_conf.set_time(epoch);
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);

        // Advance virtual time to 79% of DEFAULT_SHORT_TTLs records). This should NOT expire anything or trigger probes
        let mut fraction = RRLifecycle::Created.next_ttl_fraction() - 0.01;
        let mut now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        debug!("Elapsed time: {:?}", epoch.saturating_duration_since(now));
        zero_conf.set_time(now);
        let (mut cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);

        // Set virtual time to 81% of DEFAULT_SHORT_TTLs records (97s) . This should trigger probes for the 80% block.
        fraction = RRLifecycle::Created.next_ttl_fraction() + 0.01;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 4);
        for cmd in &cmds {
            match cmd {
                ZeroConfigCommand::DnsQuery { .. } => {}
                unexpected => {
                    panic!("Unexpected command {unexpected:?}");
                }
            }
        }

        // Set virtual time to 83% of DEFAULT_SHORT_TTLs records (99s). This should trigger NO probes since they were
        // already sent.
        fraction = RRLifecycle::Created.next_ttl_fraction() + 0.03;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);

        // Set virtual time to 87% of DEFAULT_SHORT_TTLs records. This should trigger probes again for the 85% block.
        fraction = RRLifecycle::Probed80.next_ttl_fraction() + 0.02;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 4);
        for cmd in &cmds {
            match cmd {
                ZeroConfigCommand::DnsQuery { .. } => {}
                unexpected => {
                    panic!("Unexpected command {unexpected:?}");
                }
            }
        }

        // Set virtual time to 88% of DEFAULT_SHORT_TTLs records. This should trigger NO probes since they were
        // already sent for the 85% block.
        fraction = RRLifecycle::Probed80.next_ttl_fraction() + 0.02;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);

        // Set virtual time to 90% of DEFAULT_SHORT_TTLs records. This should trigger probes again for the 90% block.
        fraction = RRLifecycle::Probed90.next_ttl_fraction();
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 4);
        for cmd in &cmds {
            match cmd {
                ZeroConfigCommand::DnsQuery { .. } => {}
                unexpected => {
                    panic!("Unexpected command {unexpected:?}");
                }
            }
        }

        // Set virtual time to 91% of DEFAULT_SHORT_TTLs records. This should trigger NO probes since they were
        // already sent for the 90% block.
        fraction = RRLifecycle::Probed90.next_ttl_fraction() + 0.01;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);

        // Set virtual time to 101% of DEFAULT_SHORT_TTLs records. This should expire A, AAAA, SRV, and TXT records.
        fraction = RRLifecycle::Probed95.next_ttl_fraction() + 0.01;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);

        let delete_cmd = cmds.first().unwrap();
        match delete_cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(service.instance_name, *instance_name);
                assert_eq!(service.service_type, *service_type);
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {:?}", delete_cmd);
            }
        }

        assert_eq!(zero_conf.store.ptrs.len(), 1);
        assert_eq!(zero_conf.store.ipv6s.len(), 0);
        assert_eq!(zero_conf.store.ipv4s.len(), 0);
        assert_eq!(zero_conf.store.srvs.len(), 0);
        assert_eq!(zero_conf.store.txts.len(), 0);

        // Now let's see about PTR probes
        fraction = RRLifecycle::Created.next_ttl_fraction() + 0.01;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        for cmd in &cmds {
            match cmd {
                ZeroConfigCommand::DnsQuery { .. } => {}
                unexpected => {
                    panic!("Unexpected command {unexpected:?}");
                }
            }
        }

        // At 82% nothing should happen since probe was sent.
        fraction = RRLifecycle::Created.next_ttl_fraction() + 0.02;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);

        // At 86%, another probe should be fired.
        fraction = RRLifecycle::Probed80.next_ttl_fraction() + 0.01;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        for cmd in &cmds {
            match cmd {
                ZeroConfigCommand::DnsQuery { .. } => {}
                unexpected => {
                    panic!("Unexpected command {unexpected:?}");
                }
            }
        }

        // At 87% nothing should happen since probe was sent in 85% block.
        fraction = RRLifecycle::Probed80.next_ttl_fraction() + 0.02;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);
        assert_eq!(zero_conf.store.ptrs.len(), 1);

        // At 91%, another probe should be fired.
        fraction = RRLifecycle::Probed85.next_ttl_fraction() + 0.01;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        for cmd in &cmds {
            match cmd {
                ZeroConfigCommand::DnsQuery { .. } => {}
                unexpected => {
                    panic!("Unexpected command {unexpected:?}");
                }
            }
        }

        // At 92% nothing should happen since probe was sent in previous block.
        fraction = RRLifecycle::Probed85.next_ttl_fraction() + 0.02;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);
        assert_eq!(zero_conf.store.ptrs.len(), 1);

        // At 96%, another probe should be fired.
        fraction = RRLifecycle::Probed90.next_ttl_fraction() + 0.01;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);
        for cmd in &cmds {
            match cmd {
                ZeroConfigCommand::DnsQuery { .. } => {}
                unexpected => {
                    panic!("Unexpected command {unexpected:?}");
                }
            }
        }

        // At 97% nothing should happen since probe was sent in previous block.
        fraction = RRLifecycle::Probed90.next_ttl_fraction() + 0.02;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 0);
        assert_eq!(zero_conf.store.ptrs.len(), 1);

        // Now advance time so the PTR is also expired. This should bring the store back to zero
        // entries
        fraction = RRLifecycle::Probed95.next_ttl_fraction();
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_LONG_TTL);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(0, cmds.len());
        assert_eq!(zero_conf.store.ptrs.len(), 0);

        // All the store should be empty now
        assert_eq!(zero_conf.store.ptrs.len(), 0);
        assert_eq!(zero_conf.store.ipv6s.len(), 0);
        assert_eq!(zero_conf.store.ipv4s.len(), 0);
        assert_eq!(zero_conf.store.srvs.len(), 0);
        assert_eq!(zero_conf.store.txts.len(), 0);
    }

    #[test]
    fn test_extension_then_expiration() {
        let mut zero_conf = ZeroConfig::new();

        // Let's create a service
        let port = 5555u16;
        let service = FQServiceName::new(
            "InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let fq_service = service.fq_name();
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let target = "MyTarget.local";
        let txt_attributes = TxtAttributes::new();

        let answers = vec![
            txt(&fq_service, &txt_attributes),
            a(target, ipv4),
            aaaa(target, ipv6),
            srv(&fq_service, target, port),
            ptr(&service.service_type_with_local, &fq_service),
        ];

        // Add the service with a first update
        let epoch = Instant::now();
        zero_conf.set_time(epoch);
        zero_conf.push_records(answers.clone(), vec![], vec![]);
        let (mut cmds, _) = zero_conf.tick();
        assert_eq!(cmds.len(), 1);

        // Advance time by 50% of short ttl, add service again
        let mut fraction = 0.5;
        let mut now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        zero_conf.push_records(answers.clone(), vec![], vec![]);
        (cmds, _) = zero_conf.tick();
        assert_eq!(0, cmds.len());

        // Advance time to when things should have been expired by now but the update should have extended the TTLs
        fraction = 1.5;
        now = epoch + Duration::from_secs_f64(fraction * DEFAULT_SHORT_TTL);
        zero_conf.set_time(now);
        zero_conf.push_records(answers.clone(), vec![], vec![]);
        (cmds, _) = zero_conf.tick();
        assert_eq!(0, cmds.len());

        now = epoch + Duration::from_secs_f64(DEFAULT_LONG_TTL * 2.0);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(1, cmds.len());

        let delete_cmd = cmds.first().unwrap();
        match delete_cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(service.instance_name, *instance_name);
                assert_eq!(service.service_type, *service_type);
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {:?}", delete_cmd);
            }
        }
        // Should be expiration

        // All the store should be empty now
        assert_eq!(zero_conf.store.ptrs.len(), 0);
        assert_eq!(zero_conf.store.ipv6s.len(), 0);
        assert_eq!(zero_conf.store.ipv4s.len(), 0);
        assert_eq!(zero_conf.store.srvs.len(), 0);
        assert_eq!(zero_conf.store.txts.len(), 0);
    }

    #[allow(clippy::too_many_arguments)]
    fn create_service(
        now: Instant,
        zero_conf: &mut ZeroConfig,
        service: &FQServiceName,
        port: u16,
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
        target: &str,
        txt_attributes: &TxtAttributes,
    ) -> Vec<ZeroConfigCommand> {
        let mut answers = Vec::new();
        let fq_service = service.fq_name();
        answers.push(txt(&fq_service, txt_attributes));
        let ipv4s = vec![ipv4];
        for addr in &ipv4s {
            answers.push(a(target, *addr));
        }
        let ipv6s = vec![ipv6];
        for addr in &ipv6s {
            answers.push(aaaa(target, *addr));
        }
        answers.push(srv(&fq_service, target, port));
        answers.push(ptr_with_ttl(
            &service.service_type_with_local,
            &fq_service,
            DEFAULT_SHORT_TTL as u32,
        ));

        zero_conf.set_time(now);
        zero_conf.push_records(answers, vec![], vec![]);
        let (cmd, _) = zero_conf.tick();
        cmd
    }

    #[test]
    fn test_multiple_devices() {
        let mut zero_conf = ZeroConfig::new();
        let epoch = Instant::now();
        let mut now = epoch;

        let port = 5555u16;
        let service = FQServiceName::new(
            "D1_InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let target = "MyTarget.local";
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let mut txt_attributes = TxtAttributes::new();
        txt_attributes.insert("key".to_owned(), "value".to_owned());
        txt_attributes.insert("key2".to_owned(), "value2".to_owned());
        let mut cmds = create_service(
            now,
            &mut zero_conf,
            &service,
            port,
            ipv4,
            ipv6,
            target,
            &txt_attributes,
        );

        assert_ne!(cmds.len(), 0);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port: p,
                txt,
            } => {
                assert_eq!(instance_name, &service.instance_name);
                assert_eq!(service_type, &service.service_type);
                assert_eq!(port, *p);
                assert_eq!(txt, &txt_attributes);
                assert!(ipv4s.contains(&ipv4));
                assert_eq!(1, ipv4s.len());
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(1, ipv6s.len());
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        };

        now = epoch + Duration::from_secs(20);
        let d2_port = 6666u16;
        let d2_service = FQServiceName::new(
            "D2_InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let d2_target = "D2_MyTarget.local";
        let d2_ipv4 = Ipv4Addr::new(127, 0, 0, 2);
        let d2_ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2);
        let mut d2_txt_attributes = TxtAttributes::new();
        d2_txt_attributes.insert("key".to_owned(), "value".to_owned());
        d2_txt_attributes.insert("key2".to_owned(), "value2".to_owned());
        cmds = create_service(
            now,
            &mut zero_conf,
            &d2_service,
            d2_port,
            d2_ipv4,
            d2_ipv6,
            d2_target,
            &d2_txt_attributes,
        );
        assert_eq!(cmds.len(), 1);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port: p,
                txt,
            } => {
                assert_eq!(instance_name, &d2_service.instance_name);
                assert_eq!(service_type, &d2_service.service_type);
                assert_eq!(d2_port, *p);
                assert_eq!(txt, &d2_txt_attributes);
                assert!(ipv4s.contains(&d2_ipv4));
                assert_eq!(1, ipv4s.len());
                assert!(ipv6s.contains(&d2_ipv6));
                assert_eq!(1, ipv6s.len());
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        };

        // Make sure first record expires
        now = epoch + Duration::from_secs(122);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();

        assert_eq!(6, cmds.len());
        let delete_cmd = cmds.first().unwrap();
        match delete_cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(service.instance_name, *instance_name);
                assert_eq!(service.service_type, *service_type);
                assert_eq!(0, zero_conf.commands.len())
            }
            ZeroConfigCommand::DnsQuery { .. } => {}
            _ => {
                panic!("Unexpected command {:?}", delete_cmd);
            }
        }

        // Now expire the second record
        now = epoch + Duration::from_secs(152);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        assert_eq!(1, cmds.len());
        let delete_cmd = cmds.first().unwrap();
        match delete_cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(d2_service.instance_name, *instance_name);
                assert_eq!(d2_service.service_type, *service_type);
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {:?}", delete_cmd);
            }
        }
    }

    #[test]
    fn test_multiple_services() {
        let mut zero_conf = ZeroConfig::new();
        let epoch = Instant::now();
        let mut now = epoch;

        let port_tls = 5555u16;
        let service_tls = FQServiceName::new(
            "D1_InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let target = "MyTarget.local";
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let mut txt_attributes = TxtAttributes::new();
        txt_attributes.insert("key".to_owned(), "value".to_owned());
        txt_attributes.insert("key2".to_owned(), "value2".to_owned());
        let mut cmds = create_service(
            now,
            &mut zero_conf,
            &service_tls,
            port_tls,
            ipv4,
            ipv6,
            target,
            &txt_attributes,
        );

        assert_eq!(cmds.len(), 1);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port: p,
                txt,
            } => {
                assert_eq!(instance_name, &service_tls.instance_name);
                assert_eq!(service_type, &service_tls.service_type);
                assert_eq!(port_tls, *p);
                assert_eq!(txt, &txt_attributes);
                assert!(ipv4s.contains(&ipv4));
                assert_eq!(1, ipv4s.len());
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(1, ipv6s.len());
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        };

        let port_tcp = 5554u16;
        let service_tcp = FQServiceName::new(
            "D1_InstanceName".to_string(),
            TCP_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        now = epoch + Duration::from_secs(60);
        cmds = create_service(
            now,
            &mut zero_conf,
            &service_tcp,
            port_tcp,
            ipv4,
            ipv6,
            target,
            &txt_attributes,
        );

        assert_eq!(cmds.len(), 1);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port: p,
                txt,
            } => {
                assert_eq!(instance_name, &service_tcp.instance_name);
                assert_eq!(service_type, &service_tcp.service_type);
                assert_eq!(port_tcp, *p);
                assert_eq!(txt, &txt_attributes);
                assert!(ipv4s.contains(&ipv4));
                assert_eq!(1, ipv4s.len());
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(1, ipv6s.len());
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        };

        now = epoch + Duration::from_secs(121);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        let delete_cmd = cmds.first().unwrap();
        match delete_cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(service_tls.instance_name, *instance_name);
                assert_eq!(service_tls.service_type, *service_type);
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {:?}", delete_cmd);
            }
        }

        now = epoch + Duration::from_secs(181);
        zero_conf.set_time(now);
        (cmds, _) = zero_conf.tick();
        let delete_cmd = cmds.first().unwrap();
        match delete_cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(service_tcp.instance_name, *instance_name);
                assert_eq!(service_tcp.service_type, *service_type);
                assert_eq!(0, zero_conf.commands.len())
            }
            _ => {
                panic!("Unexpected command {:?}", delete_cmd);
            }
        }
    }

    #[test]
    fn test_on_stop() {
        let mut zero_conf = ZeroConfig::new();
        let epoch = Instant::now();
        let mut now = epoch;

        let port_tls = 5555u16;
        let service_tls = FQServiceName::new(
            "D1_InstanceName".to_string(),
            TLS_CONNECT_SERVICE.to_string(),
            "local".to_string(),
        );
        let target = "MyTarget.local";
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let mut txt_attributes = TxtAttributes::new();
        txt_attributes.insert("key".to_owned(), "value".to_owned());
        txt_attributes.insert("key2".to_owned(), "value2".to_owned());
        let cmds = create_service(
            now,
            &mut zero_conf,
            &service_tls,
            port_tls,
            ipv4,
            ipv6,
            target,
            &txt_attributes,
        );

        assert_eq!(cmds.len(), 1);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                port: p,
                txt,
            } => {
                assert_eq!(instance_name, &service_tls.instance_name);
                assert_eq!(service_type, &service_tls.service_type);
                assert_eq!(port_tls, *p);
                assert_eq!(txt, &txt_attributes);
                assert!(ipv4s.contains(&ipv4));
                assert_eq!(1, ipv4s.len());
                assert!(ipv6s.contains(&ipv6));
                assert_eq!(1, ipv6s.len());
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        };

        now += Duration::from_secs(2);
        zero_conf.set_time(now);

        let cmds = zero_conf.on_stop();
        assert_eq!(cmds.len(), 1);
        let cmd_delete = cmds.first().unwrap();
        match cmd_delete {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(service_tls.instance_name, *instance_name);
                assert_eq!(service_tls.service_type, *service_type);
            }
            _ => {
                panic!("Unexpected command {:?}", cmd_delete);
            }
        }
    }
}
