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
use std::collections::HashSet;

use igd;
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
                    // If the socket address is unspecified we add an address for every local
                    // interface. We also ask the interface's IGD gateway (if there is one) for
                    // an address.
                    for iface_v4 in mapping_context::interfaces_v4(&mc) {
                        let local_iface_addr = net::SocketAddrV4::new(iface_v4.addr, local_addr.port());
                        endpoints.push(MappedSocketAddr {
                            addr: SocketAddr(net::SocketAddr::V4(local_iface_addr)),
                            nat_restricted: false,
                        });
                        if let Some(gateway) = iface_v4.gateway {
                            match gateway.get_any_address(igd::PortMappingProtocol::UDP,
                                                          local_iface_addr, 0,
                                                          "rust nat_traversal")
                            {
                                Ok(external_addr) => {
                                    endpoints.push(MappedSocketAddr {
                                        addr: SocketAddr(net::SocketAddr::V4(external_addr)),
                                        nat_restricted: false,
                                    });
                                },
                                Err(_) => {
                                    // TODO(canndrew): report this error
                                }
                            }
                        };
                    };
                }
                else {
                    let local_addr_v4 = net::SocketAddrV4::new(ipv4_addr, local_addr.port());
                    endpoints.push(MappedSocketAddr {
                        addr: SocketAddr(net::SocketAddr::V4(local_addr_v4)),
                        nat_restricted: false,
                    });

                    // If the local address is the address of an interface then we can avoid
                    // searching for an IGD gateway, just reuse the search result from when we
                    // found this interface.
                    let mut gateway_opt_opt = None;
                    for iface_v4 in mapping_context::interfaces_v4(&mc) {
                        if iface_v4.addr == ipv4_addr {
                            gateway_opt_opt = Some(iface_v4.gateway);
                            break;
                        }
                    };
                    let gateway_opt = match gateway_opt_opt {
                        Some(gateway_opt) => gateway_opt,
                        // We don't where this local address came from so search for an IGD gateway
                        // at it.(
                        None => {
                            match igd::search_gateway_from_timeout(ipv4_addr, Duration::from_secs(1)) {
                                Ok(gateway) => Some(gateway),
                                Err(_) => {
                                    // TODO(canndrew): report this error
                                    None
                                }
                            }
                        }
                    };
                    // If we have a gateway, ask it for an external address.
                    if let Some(gateway) = gateway_opt {
                        match gateway.get_any_address(igd::PortMappingProtocol::UDP,
                                                      local_addr_v4, 0,
                                                      "rust nat_traversal")
                        {
                            Ok(external_addr) => {
                                endpoints.push(MappedSocketAddr {
                                    addr: SocketAddr(net::SocketAddr::V4(external_addr)),
                                    nat_restricted: false,
                                });
                            },
                            Err(_) => {
                                // TODO(canndrew): report this error
                            }
                        }
                    };
                };
            },
            IpAddr::V6(ipv6_addr) => {
                if socket_utils::ipv6_is_unspecified(&ipv6_addr) {
                    // If the socket address is unspecified add an address for every interface.
                    for iface_v6 in mapping_context::interfaces_v6(&mc) {
                        let local_iface_addr = net::SocketAddr::V6(net::SocketAddrV6::new(iface_v6.addr, local_addr.port(), 0, 0));
                        endpoints.push(MappedSocketAddr {
                            addr: SocketAddr(local_iface_addr),
                            nat_restricted: false,
                        });
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

        const MAX_DATAGRAM_SIZE: usize = 256;

        let send_data = unwrap_result!(serialise(&ListenerRequest::EchoExternalAddr));
        let mut simple_servers: HashSet<SocketAddr> = mapping_context::simple_servers(&mc)
                                                                      .into_iter().collect();
        let mut deadline = time::SteadyTime::now();
        // Ping all the simple servers and waiting for a response.
        // Run this loop at most 8 times for a maximum timeout of 250ms * 8 == 2 seconds.
        let mut attempt = 0;
        let mut max_attempts = 8;
        while attempt < max_attempts && simple_servers.len() > 0 {
            attempt += 1;
            deadline = deadline + time::Duration::milliseconds(250);

            // TODO(canndrew): We should limit the number of servers that we send to. If the user
            // has added two thousand servers we really don't want to be pinging all of them. We
            // should be smart about it though and try to ping servers that are on different
            // networks, not just the first ten in the list or something.
            for simple_server in &simple_servers {
                // TODO(canndrew): What should we do if we get a partial write?
                let _ = try!(socket.send_to(&send_data[..], &**simple_server));
            };
            let mut recv_data = [0u8; MAX_DATAGRAM_SIZE];
            loop {
                let (read_size, recv_addr) = match try!(socket.recv_until(&mut recv_data[..], deadline)) {
                    Some(res) => res,
                    None => break,
                };
                if let Ok(ListenerResponse::EchoExternalAddr { external_addr }) =
                       deserialise::<ListenerResponse>(&recv_data[..read_size]) {
                    // Don't ping this simple server again while mapping this socket.
                    simple_servers.remove(&recv_addr);

                    // If the address that responded to us is global then drop max_attempts to exit
                    // the loop more quickly. The logic here is that global addresses are the ones
                    // that are likely to take the longest to respond and they're all likely to
                    // give us the same address. By contrast, servers on the same subnet as us or
                    // behind the same carrier-level NAT are likely to respond in under a second.
                    // So once we have one global address drop the timeout.
                    // TODO(canndrew): For now this is commented-out. Waiting for the is_global
                    // method to become available in the next stable rust.
                    /*
                    if recv_addr.ip().is_global() {
                        max_attempts = 4;
                    };
                    */

                    // Add this endpoint if we don't already know about it. We may have found it
                    // through IGD or it may be a local interface.
                    if endpoints.iter().all(|e| e.addr != external_addr) {
                        endpoints.push(MappedSocketAddr {
                            addr: external_addr,
                            // TODO(canndrew): We should consider ways to determine whether this is
                            // actually an restricted port. For now, just assume it's restricted. It
                            // usually will be.
                            nat_restricted: true,
                        });
                    }
                }
            }
        }

        Ok(MappedUdpSocket {
            socket: socket,
            endpoints: endpoints,
        })
    }

    /// Create a new `MappedUdpSocket`
    pub fn new(mc: &MappingContext) -> io::Result<MappedUdpSocket> {
        Self::map(try!(UdpSocket::bind("0.0.0.0:0")), mc)
    }
}
