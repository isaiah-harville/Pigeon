fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let schemas = [
        "../proto/pigeon/wire/v1/identity.proto",
        "../proto/pigeon/wire/v1/pairwise.proto",
        "../proto/pigeon/wire/v1/transport.proto",
        "../proto/pigeon/wire/v1/group.proto",
        "../proto/pigeon/wire/v1/client.proto",
    ];
    prost_build::Config::new()
        .protoc_executable(protoc)
        .compile_protos(&schemas, &["../proto"])?;

    for schema in schemas {
        println!("cargo:rerun-if-changed={schema}");
    }
    Ok(())
}
