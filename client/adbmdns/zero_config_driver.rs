use crate::zero_config::ZeroConfigCommand::CreateService;
use crate::zero_config::ZeroConfigCommand::DeleteService;
use crate::zero_config::ZeroConfigCommand::DnsQuery;
use crate::zero_config::{ZeroConfig, ZeroConfigCommand};
use crate::{send_update, AdbMdnsUpdate};
use anyhow::Result;
use libc::c_int;
use log::warn;
use simple_dns::{Name, Packet, Question};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::thread;
use std::time::Duration;

pub struct ZeroConfigDriver {
    zero_config: ZeroConfig,
}

const MDNS_PORT: u16 = 5353;
const MDNS_ADDRESS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

impl ZeroConfigDriver {
    pub fn new(zero_config: ZeroConfig) -> ZeroConfigDriver {
        ZeroConfigDriver { zero_config }
    }

    fn send_query(&self, query: &[u8]) -> std::io::Result<()> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into())?;

        let dest = SocketAddrV4::new(MDNS_ADDRESS, MDNS_PORT);
        socket.send_to(query, &dest.into())?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let mut socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        let addr = SocketAddrV4::new(MDNS_ADDRESS, MDNS_PORT);
        socket.bind(&addr.into())?;

        log::debug!("new socket bind={}, local={:?}", &addr, socket.local_addr()?);

        let multicast_group = Ipv4Addr::new(224, 0, 0, 251);
        socket.join_multicast_v4(&multicast_group, &Ipv4Addr::new(0, 0, 0, 0))?;

        // Check if ZeroConf has some commands to run before we start
        for command in self.zero_config.initial_commands() {
            self.process_command(&command);
        }

        let mut buf = [0u8; 65535];
        loop {
            let len = socket.read(&mut buf)?;
            let mdns_reply = Packet::parse(&buf[0..len])?;

            let commands = self.zero_config.update(
                mdns_reply.answers,
                mdns_reply.additional_records,
                mdns_reply.name_servers,
            );

            for command in commands {
                self.process_command(&command);
            }
        }
    }

    pub fn run_forever(mut self) {
        thread::spawn(move || loop {
            match self.run() {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                }
            }
            thread::sleep(Duration::from_secs(4));
        });
    }

    fn process_command(&self, command: &ZeroConfigCommand) {
        log::debug!("Processing command {:?}", command);
        match command {
            DnsQuery { query, qtype, qclass } => {
                let mut packet = Packet::new_query(0);
                let Ok(name) = Name::new(query.as_str()) else {
                    warn!("Query {query} cannot be made into a name");
                    return;
                };

                let question = Question::new(name, *qtype, *qclass, false);
                packet.questions.push(question.clone());
                let Ok(query) = packet.build_bytes_vec() else {
                    warn!("Unable to build query for {query}, {:?}, {:?}", qtype, qclass);
                    return;
                };

                let res = self.send_query(&query);
                if res.is_err() {
                    warn!("Error sending query {:?}", question);
                }
            }
            CreateService { instance_name, service_type, ipv4, ipv6, port } => {
                let owned_ipv4s: Vec<Ipv4Addr> = vec![*ipv4];
                let owned_ipv6s: Vec<Ipv6Addr> = vec![*ipv6];
                send_update(
                    AdbMdnsUpdate::Create,
                    instance_name,
                    service_type,
                    &owned_ipv4s,
                    &owned_ipv6s,
                    *port as c_int,
                )
            }
            DeleteService { instance_name, service_type } => {
                send_update(AdbMdnsUpdate::Delete, instance_name, service_type, &[], &[], 0)
            }
        }
    }
}
