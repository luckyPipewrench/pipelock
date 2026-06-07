fn main() {
    // The schema is vendored into the crate root so the crate is self-contained
    // for `cargo publish`. Watch the in-crate copy, not the canonical source
    // outside the crate (which is absent when building from a published crate).
    println!("cargo:rerun-if-changed=audit-packet-v0.json");
}
