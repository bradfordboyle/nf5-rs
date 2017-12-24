extern crate pnet_macros;
extern crate syntex;

use std::env;
use std::path::Path;

fn main() {
    let mut registry = syntex::Registry::new();
    pnet_macros::register(&mut registry);

    let src = Path::new("src/packet/netflow.rs.in");
    let dst = Path::new(&env::var_os("OUT_DIR").unwrap()).join("netflow.rs");

    registry.expand("", &src, &dst).unwrap();
}
