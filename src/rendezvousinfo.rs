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

use mappedsocketaddr::MappedSocketAddr;

/// Info needed by both parties when performing a rendezvous connection.
pub struct RendezvousInfo {
    /// A vector of all the mapped addresses that the peer can try connecting to.
    endpoints: Vec<MappedSocketAddr>,
    /// Used to identify the peer.
    secret: [u8; 4],
}

impl RendezvousInfo {
    /// Create rendezvous info for being sent to the remote peer.
    pub fn from_endpoints(endpoints: Vec<MappedSocketAddr>) -> RendezvousInfo {
        unimplemented!();
    }
}

pub fn decompose(info: RendezvousInfo) -> (Vec<MappedSocketAddr>, [u8; 4]) {
    let RendezvousInfo { endpoints, secret } = info;
    (endpoints, secret)
}
