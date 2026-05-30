fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../proto";
    tonic_build::configure()
        .build_server(true)
        .compile_protos(
            &[
                "cryptooffload/v1/common.proto",
                "cryptooffload/v1/key_service.proto",
                "cryptooffload/v1/sign_service.proto",
                "cryptooffload/v1/cms_service.proto",
                "cryptooffload/v1/scep_service.proto",
            ],
            &[proto_root],
        )?;
    Ok(())
}
