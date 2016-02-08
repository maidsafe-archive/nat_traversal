// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! # `nat_traversal`
//! NAT traversal utilities.

use std::io;
use std::net::UdpSocket;

use socket_addr::SocketAddr;

use periodic_sender::PeriodicSender;
use rendezvous_info::{PrivRendezvousInfo, PubRendezvousInfo};
use rendezvous_info;
use socket_utils::RecvUntil;

#[derive(Debug, RustcEncodable, RustcDecodable)]
struct HolePunch {
    pub secret: [u8; 4],
    pub ack: bool,
}

// TODO All this function should be returning is either an Ok(()) or Err(..)
/// Returns the socket along with the peer's SocketAddr
fn blocking_udp_punch_hole(udp_socket: UdpSocket,
                           our_secret: [u8; 4],
                           their_secret: [u8; 4],
                           peer_addr: SocketAddr)
                           -> (UdpSocket, io::Result<SocketAddr>) {
    // Cbor seems to serialize into bytes of different sizes and
    // it sometimes exceeded 16 bytes, let's be safe and use 128.
    const MAX_DATAGRAM_SIZE: usize = 128;

    let send_data = {
        let hole_punch = HolePunch {
            secret: our_secret,
            ack: false,
        };
        let mut enc = ::cbor::Encoder::from_memory();
        enc.encode(::std::iter::once(&hole_punch)).unwrap();
        enc.into_bytes()
    };

    assert!(send_data.len() <= MAX_DATAGRAM_SIZE,
            format!("Data exceed MAX_DATAGRAM_SIZE in blocking_udp_punch_hole: {} > {}",
                    send_data.len(),
                    MAX_DATAGRAM_SIZE));

    let addr_res: io::Result<SocketAddr> = ::crossbeam::scope(|scope| {
        let sender = try!(udp_socket.try_clone());
        let receiver = try!(udp_socket.try_clone());
        let periodic_sender = PeriodicSender::start(sender,
                                                    peer_addr,
                                                    scope,
                                                    send_data,
                                                    ::std::time::Duration::from_millis(500));

        let addr_res: io::Result<Option<SocketAddr>> =
            (|| {
                let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
                let mut peer_addr: Option<SocketAddr> = None;
                let deadline = ::time::SteadyTime::now() + ::time::Duration::seconds(2);
                loop {
                    let (read_size, addr) = match try!(receiver.recv_until(&mut recv_data[..],
                                                                           deadline)) {
                        Some(x) => x,
                        None => {
                            return Ok(peer_addr);
                        }
                    };

                    match ::cbor::Decoder::from_reader(&recv_data[..read_size])
                              .decode::<HolePunch>()
                              .next() {
                        Some(Ok(ref hp)) => {
                            if hp.secret == our_secret && hp.ack {
                                return Ok(Some(addr));
                            }
                            if hp.secret == their_secret {
                                let send_data = {
                                    let hole_punch = HolePunch {
                                        secret: their_secret,
                                        ack: true,
                                    };
                                    let mut enc = ::cbor::Encoder::from_memory();
                                    enc.encode(::std::iter::once(&hole_punch)).unwrap();
                                    enc.into_bytes()
                                };
                                periodic_sender.set_payload(send_data);
                                periodic_sender.set_destination(addr);
                                // TODO Do not do this. The only thing we should do is make
                                // sure the supplied peer_addr to this function is == to this
                                // addr (which can be spoofed anyway so additionally verify the
                                // secret above), otherwise it would mean we are connecting to
                                // someone who we are not sending HolePunch struct to
                                // TODO(canndrew): Actually it makes sense that their HolePunch
                                // message might come from an unexpected address. Instead we should
                                // sign these messages to make sure we are talking to the right
                                // person.
                                peer_addr = Some(addr);
                            } else {
                                info!("udp_hole_punch non matching secret");
                            }
                        }
                        x => {
                            info!("udp_hole_punch received invalid data: {:?}", x);
                        }
                    };
                }
            })();
        match addr_res {
            Err(e) => Err(e),
            Ok(Some(x)) => Ok(x),
            Ok(None) => {
                Err(io::Error::new(io::ErrorKind::TimedOut,
                                   "Timed out waiting for rendevous connection"))
            }
        }
    });

    (udp_socket, addr_res)
}

/// A udp socket that has been hole punched.
pub struct PunchedUdpSocket {
    /// The UDP socket.
    pub socket: UdpSocket,
    /// The remote address that this socket is able to send messages to and receive messages from.
    pub peer_addr: SocketAddr,
}

impl PunchedUdpSocket {
    /// Punch a udp socket using a mapped socket and the peer's rendezvous info.
    pub fn punch_hole(mut socket: UdpSocket,
                      our_priv_rendezvous_info: PrivRendezvousInfo,
                      their_pub_rendezvous_info: PubRendezvousInfo)
        -> io::Result<PunchedUdpSocket> {
        let (endpoints, their_secret)
            = rendezvous_info::decompose(their_pub_rendezvous_info);
        let our_secret
            = rendezvous_info::get_priv_secret(our_priv_rendezvous_info);

        for endpoint in endpoints {
            let addr = endpoint.addr;
            let (s, r) = blocking_udp_punch_hole(socket, our_secret.clone(),
                                                 their_secret.clone(), addr);
            socket = s;
            if let Ok(peer_addr) = r {
                return Ok(PunchedUdpSocket {
                    socket: socket,
                    peer_addr: peer_addr
                });
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut,
                           "Timed out waiting for rendevous connection"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use rand;

    use mapping_context::MappingContext;
    use mapped_udp_socket::MappedUdpSocket;
    use punched_udp_socket::PunchedUdpSocket;
    use rendezvous_info::gen_rendezvous_info;

    fn two_peers_punch_hole_over_loopback() {
        let mapping_context = unwrap_result!(MappingContext::new().result_discard());
        let mapped_socket_0 = unwrap_result!(MappedUdpSocket::new(&mapping_context).result_discard());
        let mapped_socket_1 = unwrap_result!(MappedUdpSocket::new(&mapping_context).result_discard());

        let socket_0 = mapped_socket_0.socket;
        let socket_1 = mapped_socket_1.socket;
        let (priv_info_0, pub_info_0) = gen_rendezvous_info(mapped_socket_0.endpoints);
        let (priv_info_1, pub_info_1) = gen_rendezvous_info(mapped_socket_1.endpoints);

        let (tx_0, rx_0) = mpsc::channel();
        let (tx_1, rx_1) = mpsc::channel();

        let jh_0 = thread!("two_peers_hole_punch_over_loopback punch socket 0", move || {
            let res = PunchedUdpSocket::punch_hole(socket_0,
                                                   priv_info_0,
                                                   pub_info_1);
            tx_0.send(res);
        });
        let jh_1 = thread!("two_peers_hole_punch_over_loopback punch socket 1", move || {
            let res = PunchedUdpSocket::punch_hole(socket_1,
                                                   priv_info_1,
                                                   pub_info_0);
            tx_1.send(res);
        });

        thread::sleep(Duration::from_millis(500));
        let punched_socket_0 = unwrap_result!(unwrap_result!(rx_0.try_recv()));
        let punched_socket_1 = unwrap_result!(unwrap_result!(rx_1.try_recv()));

        const DATA_LEN: usize = 8;
        let data_send: [u8; DATA_LEN] = rand::random();
        let mut data_recv;
        
        // Send data from 0 to 1
        data_recv = [0u8; DATA_LEN];
        punched_socket_0.socket.send_to(&data_send[..], &*punched_socket_0.peer_addr);
        let (n, _) = unwrap_result!(punched_socket_1.socket.recv_from(&mut data_recv[..]));
        assert_eq!(n, DATA_LEN);
        assert_eq!(data_send, data_recv);

        // Send data from 1 to 0
        data_recv = [0u8; DATA_LEN];
        punched_socket_1.socket.send_to(&data_send[..], &*punched_socket_1.peer_addr);
        let (n, _) = unwrap_result!(punched_socket_0.socket.recv_from(&mut data_recv[..]));
        assert_eq!(n, DATA_LEN);
        assert_eq!(data_send, data_recv);

        unwrap_result!(jh_0.join());
        unwrap_result!(jh_1.join());
    }
}

