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

use socket_addr::SocketAddr;

use holepunchserveraddr::HolePunchServerAddr;

/// You need to create a `MappingContext` before doing any socket mapping. This
/// `MappingContext` should ideally be kept throughout the lifetime of the
/// program. Internally it caches a addresses of UPnP servers and hole punching
/// servers.
pub struct MappingContext {
    servers: RwLock<Vec<HolePunchServerAddr>>,
}

impl MappingContext {
    /// Create a new mapping context. This will block breifly while it searches
    /// the network for UPnP servers.
    pub fn new() -> MappingContext {
        unimplemented!();
    }

    /// Inform the context about external hole punching servers.
    pub fn add_servers<S>(&self, servers: S)
        where S: IntoIterator<Item=HolePunchServerAddr> {
        unimplemented!();
    }
}

pub fn simple_servers(mc: &MappingContext) -> Vec<SocketAddr> {
    mc.servers.read().unwrap().iter().filter_map(|s| match *s {
        HolePunchServerAddr::Simple(a) => {
            use std::net::SocketAddr as SA;
            Some(SocketAddr(SA::V4(a)))
        }
        // TODO: handle port mapping
        _ => None,
    }).collect()
}
