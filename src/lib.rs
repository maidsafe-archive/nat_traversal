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

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/nat_traversal/")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

// Uncomment to use Clippy
// #![feature(plugin)]
// #![plugin(clippy)]

#![allow(unused, unused_extern_crates)]

extern crate cbor;
#[macro_use]
extern crate log;
extern crate net2;
extern crate rand;
extern crate rustc_serialize;
extern crate time;
extern crate crossbeam;
#[macro_use]
extern crate maidsafe_utilities;
extern crate igd;
extern crate socket_addr;
extern crate get_if_addrs;
extern crate sodiumoxide;
extern crate libc;

pub use mappingcontext::MappingContext;
pub use holepunchserveraddr::HolePunchServerAddr;
pub use mappedsocketaddr::MappedSocketAddr;
pub use rendezvousinfo::RendezvousInfo;
pub use mappedudpsocket::MappedUdpSocket;
pub use punchedudpsocket::PunchedUdpSocket;
pub use mappedtcpsocket::{MappedTcpSocket, tcp_punch_hole};
pub use simpleudpholepunchserver::SimpleUdpHolePunchServer;

mod mappingcontext;
mod holepunchserveraddr;
mod mappedsocketaddr;
mod rendezvousinfo;
mod mappedudpsocket;
mod punchedudpsocket;
mod mappedtcpsocket;
mod simpleudpholepunchserver;
mod periodic_sender;
mod socket_utils;
mod listener_message;
