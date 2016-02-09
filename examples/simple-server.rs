#[macro_use]
extern crate maidsafe_utilities;
extern crate nat_traversal;
extern crate w_result;
extern crate rustc_serialize;

use nat_traversal::{MappingContext, SimpleUdpHolePunchServer};
use w_result::{WOk, WErr};

fn main() {
    println!("The example runs a simple rendezvous server that peers can use to connect to each other with");

    // First, we must create a mapping context.
    let mapping_context = match MappingContext::new() {
        WOk(mapping_context, warnings) => {
            for warning in warnings {
                println!("Warning when creating mapping context: {}", warning);
            }
            mapping_context
        }
        WErr(e) => {
            println!("Error creating mapping context: {}", e);
            println!("Exiting.");
            return;
        }
    };

    // Now we create the server.
    let simple_server = match SimpleUdpHolePunchServer::new(&mapping_context) {
        WOk(simple_server, warnings) => {
            for warning in warnings {
                println!("Warning when creating simple server: {}", warning);
            }
            simple_server
        },
        WErr(e) => {
            println!("Error creating simple server: {}", e);
            println!("Exiting.");
            return;
        }
    };

    // Now we print the servers known addresses
    let addresses = simple_server.addresses();
    println!("Server addresses: {:#?}", addresses);

    std::thread::park();
}

