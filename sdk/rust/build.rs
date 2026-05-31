fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(
            &[
                "cryptooffload/v1/common.proto",
                "cryptooffload/v1/key_service.proto",
                "cryptooffload/v1/sign_service.proto",
                "cryptooffload/v1/cms_service.proto",
                "cryptooffload/v1/scep_service.proto",
                "cryptooffload/v1/scep_ext_service.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
