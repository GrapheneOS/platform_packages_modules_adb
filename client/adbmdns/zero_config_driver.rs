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

use crate::rr::TxtAttributes;
use crate::zero_config::ZeroConfigCommand::{
    CreateService, DeleteService, DnsQuery, Restart, UpdateService,
};
use crate::zero_config::{ZeroConfig, ZeroConfigCommand};
use crate::zero_config_driver_channel::ZeroConfigDriverChannelReceiver;
use crate::{send_update, AdbMdnsUpdate};
use anyhow::Result;
use if_addrs::Interface;
use log::{debug, error, warn};
use mio::{net::UdpSocket, Events, Poll};
use simple_dns::{Name, Packet, Question};
use socket2::{Domain, Socket, Type};
use std::collections::HashSet;
use std::io::ErrorKind::WouldBlock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};
use std::{net, thread};

struct ZeroConfigIO {
    interface: Interface,
    socket: UdpSocket,
}

pub struct ZeroConfigDriver {
    zero_config: ZeroConfig,

    // The sockets/interfaces used to send and receive mDNS packets
    io: Vec<ZeroConfigIO>,

    // A channel allowing to received commands sent from outside zeroconfig driver.
    // Currently used to receive commands resulting from network_watch.
    command_channel: ZeroConfigDriverChannelReceiver,

    running: bool,
}

const MDNS_PORT: u16 = 5353;
const MDNS_ADDRESS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_ADDRESS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

impl ZeroConfigDriver {
    pub fn new(
        zero_config: ZeroConfig,
        command_channel: ZeroConfigDriverChannelReceiver,
    ) -> ZeroConfigDriver {
        ZeroConfigDriver { zero_config, io: Vec::new(), command_channel, running: true }
    }

    fn send_query(&self, query: &[u8]) -> Result<()> {
        for zeroconfig_io in &self.io {
            let addr: SocketAddr = match zeroconfig_io.interface.addr {
                if_addrs::IfAddr::V4(_) => SocketAddrV4::new(MDNS_ADDRESS_V4, MDNS_PORT).into(),
                if_addrs::IfAddr::V6(_) => SocketAddrV6::new(
                    MDNS_ADDRESS_V6,
                    MDNS_PORT,
                    0,
                    zeroconfig_io.interface.index.unwrap_or(0),
                )
                .into(),
            };

            let res = zeroconfig_io.socket.send_to(query, addr);
            if res.is_err() {
                log::error!("Failed to send query to zero socket {res:?}");
                continue;
            }
        }
        Ok(())
    }

    fn new_socket(addr: SocketAddr) -> Result<Socket> {
        let domain = match addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::DGRAM, None)?;

        // Play nice with other mDNS daemon that may be running on this machine.
        // Let's all share the same port.
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        socket.set_reuse_port(true)?;

        // We are going to run a select() on these so let's make them non-blocking
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        Ok(socket)
    }

    fn create_socket(interface: &Interface) -> Result<UdpSocket> {
        let ip_address = &interface.ip();
        match ip_address {
            IpAddr::V4(ip) => {
                let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
                let sock = ZeroConfigDriver::new_socket(addr.into())?;
                sock.join_multicast_v4(&MDNS_ADDRESS_V4, ip)?;
                sock.set_multicast_if_v4(ip)?;
                Ok(UdpSocket::from_std(net::UdpSocket::from(sock)))
            }
            IpAddr::V6(_) => {
                let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
                let sock = ZeroConfigDriver::new_socket(addr.into())?;
                sock.join_multicast_v6(&MDNS_ADDRESS_V6, interface.index.unwrap_or(0))?;
                sock.set_multicast_if_v6(interface.index.unwrap_or(0))?;
                Ok(UdpSocket::from_std(net::UdpSocket::from(sock)))
            }
        }
    }

    fn create_sockets(&mut self) -> Result<()> {
        let interfaces: Vec<Interface> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| !i.is_loopback() && !i.is_link_local() && i.is_oper_up())
            .collect();

        for interface in interfaces {
            let Ok(socket) = ZeroConfigDriver::create_socket(&interface) else {
                warn!("Unable to create socket for interface {interface:?}");
                continue;
            };
            debug!("Created socket {socket:?} on interface {interface:?}");
            self.io.push(ZeroConfigIO { interface, socket });
        }
        Ok(())
    }

    fn process_packet(&mut self, packet: Packet) {
        let commands = self.zero_config.update(
            Instant::now(),
            packet.answers,
            packet.additional_records,
            packet.name_servers,
        );

        for command in commands {
            self.process_command(&command);
        }
    }

    fn handle_socket_readable(&mut self, socket_id: usize) -> Result<()> {
        let mut buf = [0u8; 65535];
        // Poll is ET (Edge-Triggered), we need to drain the socket buffer until it is empty.
        loop {
            match self.io[socket_id].socket.recv(&mut buf) {
                Ok(len) => {
                    let packets = Packet::parse(&buf[..len])?;
                    self.process_packet(packets);
                }
                Err(e) => {
                    if e.kind() != WouldBlock {
                        error!("Error in receiving on ZeroConfigDriverChannelReceiver: {e}");
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    fn process_events(&mut self, events: &Events) -> Result<()> {
        for event in events.iter() {
            if !event.is_readable() {
                continue;
            }

            // This is the interrupt socket. We have command waiting to be processed in the
            // command_channel.
            if event.token() == mio::Token(self.io.len()) {
                let commands = self.command_channel.recv();
                for command in &commands {
                    self.process_command(command);
                }
                continue;
            }

            self.handle_socket_readable(event.token().0)?;
        }
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        debug!("ZeroConfigDriver starting...");
        self.running = true;
        self.create_sockets()?;

        // Check if ZeroConf has some commands to run before we start. This is the time to send
        // the initial query for tracked services.
        for command in self.zero_config.on_start() {
            self.process_command(&command);
        }

        let mut poller = Poll::new()?;

        // Register all network interfaces
        for (index, interface) in self.io.iter_mut().enumerate() {
            poller.registry().register(
                &mut interface.socket,
                mio::Token(index),
                mio::Interest::READABLE,
            )?;
        }

        // Register the interrupt socket
        poller.registry().register(
            &mut self.command_channel,
            mio::Token(self.io.len()),
            mio::Interest::READABLE,
        )?;

        let mut events = Events::with_capacity(self.io.len() + 1);
        while self.running {
            // TODO timeout should be set according to the attention list in ZeroConf. For now
            // we never timeout
            poller.poll(&mut events, None)?;
            self.process_events(&events)?;
        }

        debug!("ZeroConfigDriver stopping...");
        Ok(())
    }

    pub fn run_forever(mut self) {
        loop {
            match self.run() {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    fn process_command(&mut self, command: &ZeroConfigCommand) {
        log::debug!("Processing command {command:?}");
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
                    warn!("Unable to build query for {query}, {qtype:?}, {qclass:?}");
                    return;
                };

                let res = self.send_query(&query);
                if res.is_err() {
                    warn!("Error sending query {question:?} {res:?}");
                }
            }
            CreateService { instance_name, service_type, ipv4s, ipv6s, port, txt } => send_update(
                AdbMdnsUpdate::Create,
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                *port,
                txt,
            ),
            UpdateService { instance_name, service_type, ipv4s, ipv6s, port, txt } => send_update(
                AdbMdnsUpdate::Update,
                instance_name,
                service_type,
                ipv4s,
                ipv6s,
                *port,
                txt,
            ),
            DeleteService { instance_name, service_type } => send_update(
                AdbMdnsUpdate::Delete,
                instance_name,
                service_type,
                &HashSet::new(),
                &HashSet::new(),
                0,
                &TxtAttributes::new(),
            ),
            Restart {} => {
                self.running = false;
            }
        }
    }
}
