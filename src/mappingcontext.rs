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

use std::sync::RwLock;
use std::io;
use std::fmt;
use std::net::Ipv4Addr;
use std;
use std::thread;
use std::time::Duration;

use igd;
use socket_addr::SocketAddr;
use w_result::WResult::{self, WOk, WErr};
use get_if_addrs;

use holepunchserveraddr::HolePunchServerAddr;

/// You need to create a `MappingContext` before doing any socket mapping. This
/// `MappingContext` should ideally be kept throughout the lifetime of the
/// program. Internally it caches a addresses of UPnP servers and hole punching
/// servers.
pub struct MappingContext {
    servers: RwLock<Vec<HolePunchServerAddr>>,
}

/// Errors that can occur when trying to create a `MappingContext`.
#[derive(Debug)]
pub enum MappingContextNewError {
    /// Failed to list the local machine's network interfaces.
    ListInterfaces(io::Error),
    /// Failed to spawn a thread.
    SpawnThread(io::Error),
}

impl fmt::Display for MappingContextNewError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MappingContextNewError::*;
        match *self {
            ListInterfaces(ref e) => write!(f, "Failed to list the local machine's network \
                                                interfaces. get_if_addrs::get_if_addrs returned \
                                                an error: {}", e),
            SpawnThread(ref e) => write!(f, "Failed to spawn a thread. thread::spawn returned an \
                                             error: {}", e),
        }
    }
}

impl std::error::Error for MappingContextNewError {
    fn cause(&self) -> Option<&std::error::Error> {
        use self::MappingContextNewError::*;
        match *self {
            ListInterfaces(ref e) => Some(e),
            SpawnThread(ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        use self::MappingContextNewError::*;
        match *self {
            ListInterfaces(_) => "Failed to list the local machine's network interfaces",
            SpawnThread(_) => "Failed to spawn a thread",
        }
    }
}

/// Warnings that can be raised by 
#[derive(Debug)]
pub enum MappingContextNewWarning {
    SearchGateway(String, Ipv4Addr, igd::SearchError),
}

impl fmt::Display for MappingContextNewWarning {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MappingContextNewWarning::SearchGateway(ref if_name, ref if_addr, ref e)
                => write!(f, "Failed to find an IGD gateway on network interface {} {}. \
                              igd::search_gateway_from_timeout returned an error: {}",
                              if_name, if_addr, e),
        }
    }
}

impl std::error::Error for MappingContextNewWarning {
    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            MappingContextNewWarning::SearchGateway(_, _, ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        match *self {
            MappingContextNewWarning::SearchGateway(_, _, ref e) => "Failed to find IGD gateway."
        }
    }
}

impl MappingContext {
    /// Create a new mapping context. This will block breifly while it searches
    /// the network for UPnP servers.
    pub fn new() -> WResult<MappingContext, MappingContextNewWarning, MappingContextNewError> {
        let interfaces = match get_if_addrs::get_if_addrs() {
            Ok(if_addrs) => if_addrs,
            Err(e) => return WErr(MappingContextNewError::ListInterfaces(e)),
        };
        let mut warnings = Vec::new();
        let mut search_threads = Vec::new();
        for interface in interfaces {
            let if_name = interface.name;
            let addr = match interface.addr {
                get_if_addrs::IfAddr::V4(v4_addr) => v4_addr.ip,
                // TODO(canndrew): Can we support IGD on ipv6?
                get_if_addrs::IfAddr::V6(_) => continue,
            };
            // TODO(canndrew): use is_loopback when it's stable
            //if addr.is_loopback() {
            if addr.octets()[0] == 127 {
                continue;
            };
            search_threads.push(thread::Builder::new()
                                                .name(From::from("IGD search"))
                                                .spawn(move || {
                match igd::search_gateway_from_timeout(addr, Duration::from_secs(1)) {
                    Ok(gateway) => Ok(gateway),
                    Err(e) => Err(MappingContextNewWarning::SearchGateway(if_name, addr, e)),
                }
            }));
        };
        let mut servers = Vec::new();
        for search_thread in search_threads {
            match search_thread {
                Err(e) => return WErr(MappingContextNewError::SpawnThread(e)),
                Ok(jh) => {
                    // If the child thread panicked, propogate the panic.
                    let res = unwrap_result!(jh.join());
                    match res {
                        Err(e) => {
                            warnings.push(e);
                        }
                        Ok(gateway) => {
                            servers.push(HolePunchServerAddr::IgdGateway(gateway));
                        }
                    }
                }
            }
        }
        let mc = MappingContext {
            servers: RwLock::new(servers),
        };
        WOk(mc, warnings)
    }

    /// Inform the context about external hole punching servers.
    pub fn add_servers<S>(&self, servers: S)
        where S: IntoIterator<Item=HolePunchServerAddr>
    {
        let mut s = unwrap_result!(self.servers.write());
        s.extend(servers)
    }
}

pub fn simple_servers(mc: &MappingContext) -> Vec<SocketAddr> {
    unwrap_result!(mc.servers.read()).iter().filter_map(|s| match *s {
        HolePunchServerAddr::Simple(a) => {
            use std::net::SocketAddr as SA;
            Some(SocketAddr(SA::V4(a)))
        }
        // TODO: handle port mapping
        _ => None,
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_mapping_context() {
        let _ = unwrap_result!(MappingContext::new().result_discard());
    }
}

