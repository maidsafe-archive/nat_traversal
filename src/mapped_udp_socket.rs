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
use std::net;
use std::time::Duration;

use time;
use get_if_addrs;
use ip::{SocketAddrExt, IpAddr};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use socket_addr::SocketAddr;

use hole_punch_server_addr::HolePunchServerAddr;
use listener_message::{ListenerRequest, ListenerResponse};
use mapping_context;
use mapping_context::MappingContext;
use mapped_socket_addr::MappedSocketAddr;
use periodic_sender::PeriodicSender;
use socket_utils;
use socket_utils::RecvUntil;

// TODO(canndrew): This should return a Vec of SocketAddrs rather than a single SocketAddr. The Vec
// should contain all known addresses of the socket.
fn external_udp_socket(udp_socket: UdpSocket,
                       peer_udp_listeners: Vec<SocketAddr>)
                       -> io::Result<(UdpSocket, Vec<SocketAddr>)> {
    const MAX_DATAGRAM_SIZE: usize = 256;

    let port = try!(udp_socket.local_addr()).port();
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
            let deadline = time::SteadyTime::now() + time::Duration::seconds(2);
            let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
            let (read_size, recv_addr) = match udp_socket.recv_until(&mut recv_data[..], deadline) {
                Ok(Some(res)) => res,
                Ok(None) => continue,
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
               -> io::Result<MappedUdpSocket>
    {
        let mut endpoints = Vec::new();

        // Add the local addresses of this socket for the sake of peers on the name machine or
        // same local network as us.
        let local_addr = try!(socket.local_addr());
        match SocketAddrExt::ip(&local_addr) {
            IpAddr::V4(ipv4_addr) => {
                if socket_utils::ipv4_is_unspecified(&ipv4_addr) {
                    for iface_addr in mapping_context::if_addrs(mc) {
                        match *iface_addr {
                            IpAddr::V4(ipv4_addr) => {
                                endpoints.push(MappedSocketAddr {
                                    addr: SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(ipv4_addr, local_addr.port()))),
                                    nat_restricted: false,
                                });
                            }
                            IpAddr::V6(_) => (),
                        };
                    };
                }
                else {
                    endpoints.push(MappedSocketAddr {
                        addr: SocketAddr(net::SocketAddr::V4(net::SocketAddrV4::new(ipv4_addr, local_addr.port()))),
                        nat_restricted: false,
                    });
                }
            },
            IpAddr::V6(ipv6_addr) => {
                if socket_utils::ipv6_is_unspecified(&ipv6_addr) {
                    for iface_addr in mapping_context::if_addrs(mc) {
                        match *iface_addr {
                            IpAddr::V6(ipv6_addr) => {
                                endpoints.push(MappedSocketAddr {
                                    addr: SocketAddr(net::SocketAddr::V6(net::SocketAddrV6::new(ipv6_addr, local_addr.port(), 0, 0))),
                                    nat_restricted: false,
                                });
                            }
                            IpAddr::V4(_) => (),
                        };
                    };
                }
                else {
                    endpoints.push(MappedSocketAddr {
                        addr: SocketAddr(net::SocketAddr::V6(net::SocketAddrV6::new(ipv6_addr, local_addr.port(), 0, 0))),
                        nat_restricted: false,
                    });
                }
            },
        };

        // Try to find other endpoint addresses using hole punch servers.
        // TODO(canndrew): parallelise this. Also we don't really want to contact *all* hole
        // punching servers that we know of. We can be smarter than that.
        let servers = mapping_context::simple_servers(mc);
        external_udp_socket(socket, servers).map(|(socket, endpoints)| {
            MappedUdpSocket {
                socket: socket,
                endpoints: endpoints.into_iter().map(|a| {
                    MappedSocketAddr {
                        addr: a,
                        nat_restricted: true,
                    }
                }).collect()
            }
        })
    }

    /// Create a new `MappedUdpSocket`
    pub fn new(mc: &MappingContext) -> io::Result<MappedUdpSocket> {
        Self::map(try!(UdpSocket::bind("0.0.0.0:0")), mc)
    }
}
