fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmp = cc::Build::new();
    cmp.file("src/cmp_shim.c")
        .flag_if_supported("-Wno-deprecated-declarations");

    if let Ok(dir) = std::env::var("OPENSSL_INCLUDE_DIR") {
        cmp.include(dir);
    } else if let Ok(dir) = std::env::var("OPENSSL_DIR") {
        cmp.include(format!("{dir}/include"));
    }

    cmp.compile("cmp_shim");

    let proto_root = "../proto";
    tonic_build::configure().build_server(true).compile_protos(
        &[
            "cryptooffload/v1/common.proto",
            "cryptooffload/v1/key_service.proto",
            "cryptooffload/v1/sign_service.proto",
            "cryptooffload/v1/cms_service.proto",
            "cryptooffload/v1/cmp_service.proto",
            "cryptooffload/v1/scep_service.proto",
            "cryptooffload/v1/scep_ext_service.proto",
        ],
        &[proto_root],
    )?;
    Ok(())
}
