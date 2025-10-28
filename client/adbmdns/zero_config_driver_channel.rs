use crate::zero_config::ZeroConfigCommand;
use anyhow::Result;
use log::error;
use mio::{net::UdpSocket, Interest, Registry, Token};
use std::io::ErrorKind::WouldBlock;
use std::net;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::mpsc;

const LOOPBACK_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

pub struct ZeroConfigDriverChannelSender {
    tx: mpsc::SyncSender<ZeroConfigCommand>,
    socket: UdpSocket,
}

pub struct ZeroConfigDriverChannelReceiver {
    rx: mpsc::Receiver<ZeroConfigCommand>,
    socket: UdpSocket,
}

impl ZeroConfigDriverChannelSender {
    fn new(
        tx: mpsc::SyncSender<ZeroConfigCommand>,
        addr: SocketAddr,
    ) -> std::io::Result<ZeroConfigDriverChannelSender> {
        let local_addr = SocketAddrV4::new(LOOPBACK_V4, 0);
        let socket = net::UdpSocket::bind(local_addr)?;
        let mio_socket = UdpSocket::from_std(socket);
        let _ = mio_socket.connect(addr);
        Ok(ZeroConfigDriverChannelSender { tx, socket: mio_socket })
    }

    pub(crate) fn send(&self, cmd: ZeroConfigCommand) -> Result<()> {
        self.tx.send(cmd)?;
        let buf = [1u8];
        self.socket.send(&buf)?;
        Ok(())
    }
}

impl ZeroConfigDriverChannelReceiver {
    fn new(
        rx: mpsc::Receiver<ZeroConfigCommand>,
        socket: UdpSocket,
    ) -> ZeroConfigDriverChannelReceiver {
        ZeroConfigDriverChannelReceiver { rx, socket }
    }

    pub fn recv(&mut self) -> Vec<ZeroConfigCommand> {
        let mut buf = vec![0u8; 65535];

        // The Poller is ET (Edge-Triggered), we need to drain the socket buffer until it is empty.
        loop {
            match self.socket.recv(&mut buf) {
                Ok(_size) => {}
                Err(e) => {
                    if e.kind() != WouldBlock {
                        error!("Error in receiving on ZeroConfigDriverChannelReceiver: {e}");
                    }
                    break;
                }
            }
        }

        // Likewise, we must completely drain the channel because of the ET-only nature of the
        // poller
        let mut cmds = Vec::new();
        while let Ok(cmd) = self.rx.try_recv() {
            cmds.push(cmd);
        }

        cmds
    }
}

// To make the ZeroConfigDriverChannelReceiver pollable, we implement the Source Trait.
impl mio::event::Source for ZeroConfigDriverChannelReceiver {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        registry.register(&mut self.socket, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        registry.reregister(&mut self.socket, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> std::io::Result<()> {
        registry.deregister(&mut self.socket)
    }
}

pub fn new() -> Result<(ZeroConfigDriverChannelSender, ZeroConfigDriverChannelReceiver)> {
    let signal_addr = SocketAddrV4::new(LOOPBACK_V4, 0);
    let signal_sock = net::UdpSocket::bind(signal_addr)?;
    // Get the socket with the OS chosen port
    let signal_addr = signal_sock.local_addr()?;
    signal_sock.set_nonblocking(true)?;

    let mio_sock = UdpSocket::from_std(signal_sock);

    let (tx, rx) = mpsc::sync_channel::<ZeroConfigCommand>(100);
    let sender = ZeroConfigDriverChannelSender::new(tx, signal_addr)?;
    let receiver = ZeroConfigDriverChannelReceiver::new(rx, mio_sock);

    Ok((sender, receiver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_send_and_receive_single_command() {
        let (sender, mut receiver) = new().unwrap();

        let cmd = ZeroConfigCommand::Restart {};
        let Ok(_) = sender.send(cmd.clone()) else { panic!() };

        // Give a moment for the UDP packet to be sent and received.
        thread::sleep(Duration::from_millis(10));

        let received_cmds = receiver.recv();
        assert_eq!(received_cmds.len(), 1);
        assert_eq!(received_cmds[0], cmd);

        // Make sure the channel is empty
        let received_cmds = receiver.recv();
        assert_eq!(received_cmds.len(), 0);
    }

    #[test]
    fn test_send_and_receive_multiple_commands() {
        let (sender, mut receiver) = new().unwrap();
        let cmds = vec![
            ZeroConfigCommand::Restart {},
            ZeroConfigCommand::DnsQuery {
                query: "test.local".to_string(),
                qtype: simple_dns::QTYPE::ANY,
                qclass: simple_dns::QCLASS::ANY,
            },
        ];

        for cmd in &cmds {
            let Ok(_) = sender.send(cmd.clone()) else { panic!() };
        }

        // Give a moment for the UDP packets to be sent and received.
        thread::sleep(Duration::from_millis(10));

        let received_cmds = receiver.recv();
        assert_eq!(received_cmds.len(), cmds.len());
        assert_eq!(received_cmds, cmds);

        // Make sure the channel is empty
        let received_cmds = receiver.recv();
        assert_eq!(received_cmds.len(), 0);
    }
}
