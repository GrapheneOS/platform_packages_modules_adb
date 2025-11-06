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

use anyhow::{anyhow, Result};
use simple_dns::rdata::RData::TXT as SimpleDnsTXT;
use simple_dns::rdata::RData::{A, AAAA, PTR, SRV};
use simple_dns::{Name, ResourceRecord};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::mem::take;
use std::net::{Ipv4Addr, Ipv6Addr};

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
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
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

    // TODO: The priority queue to monitor RR goes here.

    // The list of tracked services. e.g.: _adb-tls-connect._tcp
    pub(crate) tracked_services: Vec<String>,

    // Keep track of currently known services. Used to update the
    // tracker and delete all entries upon stop.
    known_instances: HashSet<AdbDomainName>,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct AdbDomainName {
    pub instance_name: String,
    pub service_type: String,
    pub local_domain: String,
}

impl AdbDomainName {
    #[allow(dead_code)]
    fn new_local(instance_name: String, service_type: String) -> AdbDomainName {
        AdbDomainName { instance_name, service_type, local_domain: "local".to_owned() }
    }
}

impl Display for AdbDomainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.instance_name, self.service_type, self.local_domain)
    }
}

impl<'a> TryFrom<&Name<'a>> for AdbDomainName {
    type Error = anyhow::Error;

    fn try_from(name: &Name<'a>) -> Result<AdbDomainName> {
        let parts = name.get_labels();
        if parts.len() != 4 {
            return Err(anyhow!("name does not have 4 parts: {name}"));
        }

        let instance_name = parts[0].to_string();
        let service = parts[1].to_string();
        let protocol = parts[2].to_string();
        let service_type = format!("{service}.{protocol}");
        let domain = parts[3].to_string();

        Ok(AdbDomainName { instance_name, service_type, local_domain: domain })
    }
}

const TLS_CONNECT_SERVICE: &str = "_adb-tls-connect._tcp";
const TLS_PAIRING_SERVICE: &str = "_adb-tls-pairing._tcp";
const TCP_CONNECT_SERVICE: &str = "_adb._tcp";

pub type TxtAttributes = HashMap<String, String>;

impl ZeroConfig {
    pub(crate) fn new() -> ZeroConfig {
        let mut zero_config = ZeroConfig {
            commands: Vec::new(),
            tracked_services: Vec::new(),
            known_instances: HashSet::new(),
        };
        zero_config.track_service(TLS_CONNECT_SERVICE.to_owned());
        zero_config.track_service(TLS_PAIRING_SERVICE.to_owned());
        zero_config.track_service(TCP_CONNECT_SERVICE.to_owned());
        zero_config
    }

    pub fn on_start(&mut self) -> Vec<ZeroConfigCommand> {
        let mut commands = Vec::new();
        for service in &self.tracked_services {
            let query = format!("{service}.local");
            commands.push(ZeroConfigCommand::DnsQuery {
                query,
                qtype: simple_dns::QTYPE::ANY,
                qclass: simple_dns::QCLASS::ANY,
            });
        }
        commands
    }

    pub fn on_stop(&mut self) -> Vec<ZeroConfigCommand> {
        let mut commands = Vec::new();

        for service in &self.known_instances {
            commands.push(ZeroConfigCommand::DeleteService {
                instance_name: service.instance_name.to_string(),
                service_type: service.service_type.to_string(),
            })
        }

        self.known_instances.clear();
        commands
    }

    pub fn track_service(&mut self, service_type: String) {
        self.tracked_services.push(service_type);
    }

    fn process_records(&mut self, records: Vec<ResourceRecord>) {
        let mut instance_name: Option<String> = None;
        let mut service_type: Option<String> = None;
        let mut port = None;
        let mut a: Option<Ipv4Addr> = None;
        let mut aaaa: Option<Ipv6Addr> = None;
        let mut ttl = 0;
        let mut domain_name = None;
        let mut txt: Option<TxtAttributes> = None;

        for record in records {
            match &record.rdata {
                PTR(ptr) => {
                    log::debug!(
                        "   PTR : Name={}, TTL={}, rdata={}",
                        record.name,
                        record.ttl,
                        ptr.0
                    );
                    let service = match AdbDomainName::try_from(&ptr.0) {
                        Ok(s) => s,
                        Err(_) => {
                            log::debug!("   Discarding non-mDNS PTR: {} -> {}", record.name, ptr.0);
                            continue;
                        }
                    };
                    domain_name = Some(service.clone());

                    // Disregard all mDNS PTR that we are not tracking
                    if !self.tracked_services.contains(&service.service_type) {
                        log::debug!(
                            "   Discarding non-tracked service type: {}",
                            service.service_type
                        );
                        continue;
                    }

                    instance_name = Some(service.instance_name.to_string());
                    if record.ttl == 0 {
                        self.known_instances.remove(&service);
                        self.commands.push(ZeroConfigCommand::DeleteService {
                            instance_name: service.instance_name,
                            service_type: service.service_type,
                        });
                    }
                }
                SRV(srv) => {
                    log::debug!(
                        "   SRV : Name={}, TTL={}, Port={}, Target={}",
                        record.name,
                        record.ttl,
                        srv.port,
                        srv.target
                    );
                    let service = match AdbDomainName::try_from(&record.name) {
                        Ok(s) => s,
                        Err(e) => {
                            log::debug!(
                                "   Could not parse SRV record name '{}': {e}",
                                &record.name
                            );
                            continue;
                        }
                    };
                    instance_name = Some(service.instance_name.to_owned());
                    service_type = Some(service.service_type.to_owned());
                    port = Some(srv.port);
                    ttl = record.ttl;
                }
                A(ip) => {
                    a = Some(Ipv4Addr::from(ip.address));
                    log::debug!(
                        "   A   : Name={}, TTL={}, IP={}",
                        record.name,
                        record.ttl,
                        ip.address
                    );
                }
                AAAA(ip) => {
                    aaaa = Some(Ipv6Addr::from(ip.address));
                    log::debug!(
                        "   AAAA: Name={}, TTL={}, IP={}",
                        record.name,
                        record.ttl,
                        ip.address
                    );
                }
                SimpleDnsTXT(txt_rdata) => {
                    log::debug!("   TXT : Name={}, TTL={}", record.name, record.ttl);
                    // The dns_parser crate provides an iterator for TXT records
                    let mut kvs: TxtAttributes = HashMap::new();
                    for (key, option) in txt_rdata.attributes() {
                        let value = option.unwrap_or("".to_string());
                        log::debug!("           - {key}={value}");
                        kvs.insert(key, value);
                    }
                    txt = Some(kvs);
                }
                unknown => {
                    log::debug!("   XXX : Name={}, {unknown:?}", record.name);
                }
            }
        }

        if ttl == 0 {
            return;
        }

        if let (
            Some(instance_name),
            Some(service_type),
            Some(ipv4),
            Some(port),
            Some(ipv6),
            Some(domain_name),
            Some(txt),
        ) = (instance_name, service_type, a, port, aaaa, domain_name, txt)
        {
            self.known_instances.insert(domain_name);
            self.commands.push(ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4,
                ipv6,
                port,
                txt,
            });
        } else {
            log::debug!("Incomplete mDNS record found.")
        }
    }

    pub fn update(
        &mut self,
        answers: Vec<ResourceRecord>,
        additional: Vec<ResourceRecord>,
        nameserver: Vec<ResourceRecord>,
    ) -> Vec<ZeroConfigCommand> {
        // Combine all records from the mDNS packet into a single list for processing.
        // This allows finding related records (e.g., PTR, SRV, A/AAAA) that may be in
        // different sections of the packet.
        let all_records: Vec<_> = answers.into_iter().chain(additional).chain(nameserver).collect();
        if all_records.is_empty() {
            return Vec::new();
        }

        log::debug!("Processing {} records from mDNS packet", all_records.len());
        self.process_records(all_records);

        take(self.commands.as_mut())
    }
}

#[cfg(test)]
mod tests {
    use crate::zero_config::{AdbDomainName, ZeroConfig, ZeroConfigCommand, TLS_CONNECT_SERVICE};
    use simple_dns::rdata::RData::SRV;
    use simple_dns::rdata::{RData, A, TXT};
    use simple_dns::{Name, ResourceRecord, CLASS};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn a(name: &str, ip: Ipv4Addr) -> ResourceRecord {
        ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, 10, RData::A(A::from(ip)))
    }

    fn aaaa(name: &str, ip: Ipv6Addr) -> ResourceRecord {
        ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            10,
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
        ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, 10, SRV(srv_rdata))
    }

    fn txt<'a>(name: &'a str, body: &'a str) -> ResourceRecord<'a> {
        ResourceRecord::new(
            Name::new_unchecked(name),
            CLASS::IN,
            10,
            RData::TXT(TXT::new().with_string(body).unwrap()),
        )
    }

    fn ptr<'a>(name: &'a str, domain: &'a str, ttl: u32) -> ResourceRecord<'a> {
        let rdata_struct: simple_dns::rdata::PTR =
            simple_dns::rdata::PTR(Name::new_unchecked(domain));

        let rdata_enum = RData::PTR(rdata_struct);

        ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, ttl, rdata_enum)
    }

    #[test]
    fn test_update_nothing_discovered() {
        let mut zero_conf = ZeroConfig::new();

        let answers = vec![
            txt("_srv.local", "text"),
            a("_srv.local", Ipv4Addr::new(127, 0, 0, 1)),
            aaaa("_srv.local", Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            srv("my_server", "my_target", 5555),
            ptr("my_ptr", "my_target", 120),
        ];

        let cmds = zero_conf.update(answers, vec![], vec![]);
        assert_eq!(cmds.len(), 0);
    }

    #[test]
    fn test_update_with_discovered_service() {
        let mut zero_conf = ZeroConfig::new();
        let port = 5555u16;
        let domain_name =
            AdbDomainName::new_local("my_instance".to_owned(), TLS_CONNECT_SERVICE.to_owned());
        let domain_name_string = domain_name.to_string();
        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let target = "MyTarget.local";

        let answers = vec![
            txt("_srv.local", "text"),
            a(target, ipv4),
            aaaa(target, ipv6),
            srv(&domain_name_string, target, port),
            ptr(&domain_name.service_type, &domain_name_string, 120),
        ];

        let cmds = zero_conf.update(answers, vec![], vec![]);
        assert_ne!(cmds.len(), 0);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::CreateService {
                instance_name,
                service_type,
                ipv4: ip4,
                ipv6: ip6,
                port: p,
                txt: _,
            } => {
                assert_eq!(instance_name, &domain_name.instance_name);
                assert_eq!(service_type, &domain_name.service_type);
                assert_eq!(port, *p);
                assert_eq!(*ip4, ipv4);
                assert_eq!(*ip6, ipv6);
                assert_eq!(zero_conf.commands.len(), 0)
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        };
    }

    #[test]
    fn test_ignored_delete() {
        let mut zero_conf = ZeroConfig::new();
        let domain_name =
            AdbDomainName::new_local("my_instance".to_owned(), "chromecast._tcp".to_owned());
        let domain_name_string = domain_name.to_string();
        let answers = vec![ptr(&domain_name.service_type, &domain_name_string, 0)];
        let cmds = zero_conf.update(answers, vec![], vec![]);
        assert_eq!(cmds.len(), 0);
    }

    #[test]
    fn test_delete() {
        let mut zero_conf = ZeroConfig::new();
        let domain_name =
            AdbDomainName::new_local("my_instance".to_owned(), TLS_CONNECT_SERVICE.to_owned());
        let domain_name_string = domain_name.to_string();
        let answers = vec![ptr(&domain_name.service_type, &domain_name_string, 0)];
        let cmds = zero_conf.update(answers, vec![], vec![]);
        assert_ne!(cmds.len(), 0);
        let cmd = cmds.first().unwrap();
        match cmd {
            ZeroConfigCommand::DeleteService { instance_name, service_type } => {
                assert_eq!(*instance_name, domain_name.instance_name);
                assert_eq!(*service_type, domain_name.service_type);
                assert_eq!(zero_conf.commands.len(), 0)
            }
            _ => {
                panic!("Unexpected command {cmd:?}");
            }
        }
    }
}
