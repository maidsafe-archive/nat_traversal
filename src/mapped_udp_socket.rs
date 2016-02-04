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
use std::time::Duration;

use get_if_addrs;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use socket_addr::SocketAddr;

use hole_punch_server_addr::HolePunchServerAddr;
use listener_message::{ListenerRequest, ListenerResponse};
use mapping_context;
use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;
use periodic_sender::PeriodicSender;

// TODO(canndrew): This should return a Vec of SocketAddrs rather than a single SocketAddr. The Vec
// should contain all known addresses of the socket.
fn external_udp_socket(udp_socket: UdpSocket,
                       peer_udp_listeners: Vec<SocketAddr>)
                       -> io::Result<(UdpSocket, Vec<SocketAddr>)> {
    const MAX_DATAGRAM_SIZE: usize = 256;

    let port = try!(udp_socket.local_addr()).port();
    try!(udp_socket.set_read_timeout(Some(Duration::from_secs(2))));
    let cloned_udp_socket = try!(udp_socket.try_clone());

    let send_data = unwrap_result!(serialise(&ListenerRequest::EchoExternalAddr));

    let if_addrs: Vec<SocketAddr> = try!(get_if_addrs::get_if_addrs())
                                        .into_iter()
                                        .map(|i| SocketAddr::new(i.addr.ip(), port))
                                        .collect();

    let res = try!(::crossbeam::scope(|scope| -> io::Result<Vec<SocketAddr>> {
        // TODO Instead of periodic sender just send the request to every body and start listening.
        // If we get it back from even one, we collect the info and return.
        for udp_listener in &peer_udp_listeners {
            let cloned_udp_socket = try!(cloned_udp_socket.try_clone());
            let _periodic_sender = PeriodicSender::start(cloned_udp_socket,
                                                         *udp_listener,
                                                         scope,
                                                         &send_data[..],
                                                         ::std::time::Duration::from_millis(300));
            let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
            let (read_size, recv_addr) = match udp_socket.recv_from(&mut recv_data[..]) {
                Ok(res) => res,
                Err(_) => continue,
            };

            if let Ok(ListenerResponse::EchoExternalAddr { external_addr }) =
                   deserialise::<ListenerResponse>(&recv_data[..read_size]) {
                let mut addrs = vec![external_addr];
                addrs.extend(if_addrs);
                return Ok(addrs);
            }
        }
        Ok(if_addrs)
    }));

    Ok((udp_socket, res))
}

/// A bound udp socket for which we know our external endpoints.
pub struct MappedUdpSocket {
    /// The socket.
    pub socket: UdpSocket,
    /// The known endpoints of this socket.
    pub endpoints: Vec<MappedSocketAddr>
}

impl MappedUdpSocket {
    /// Map an existing `UdpSocket`.
    pub fn map(socket: UdpSocket, mc: &MappingContext)
               -> io::Result<MappedUdpSocket> {
        let servers = mapping_context::simple_servers(mc);
        external_udp_socket(socket, servers).map(|(socket, endpoints)| {
            MappedUdpSocket {
                socket: socket,
                endpoints: endpoints.into_iter().filter_map(|a| {
                    Some(MappedSocketAddr {
                        addr: match a.0 {
                            ::std::net::SocketAddr::V4(a) => a,
                            _ => return None,
                        },
                        nat_restricted: true,
                    })
                }).collect()
            }
        })
    }

    /// Create a new `MappedUdpSocket`
    pub fn new(mc: &MappingContext) -> io::Result<MappedUdpSocket> {
        Self::map(try!(UdpSocket::bind("0.0.0.0:0")), mc)
    }
}
