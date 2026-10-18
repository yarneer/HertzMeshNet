use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = Path::new("proto");
    let proto = proto_root.join("hz/v1/coord.proto");
    let file_descriptors = protox::compile([proto], [proto_root])?;
    tonic_prost_build::compile_fds(file_descriptors)?;
    Ok(())
}
