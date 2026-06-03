use tonic::Status;

pub fn map_key_store_err(err: anyhow::Error) -> Status {
    let msg = err.to_string();
    if msg.contains("lock poisoned") {
        return Status::unavailable(msg);
    }
    if msg.contains("key not found") {
        return Status::not_found(msg);
    }
    if msg.contains("already consumed") {
        return Status::failed_precondition(msg);
    }
    Status::invalid_argument(msg)
}

pub fn map_crypto_err(err: anyhow::Error) -> Status {
    let msg = err.to_string();
    if is_invalid_argument_crypto(&msg) {
        return Status::invalid_argument(msg);
    }
    if is_resource_exhausted_crypto(&msg) {
        return Status::resource_exhausted(msg);
    }
    if msg.contains("lock poisoned") {
        return Status::unavailable(msg);
    }
    Status::internal(msg)
}

fn is_invalid_argument_crypto(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("must not be empty")
        || m.contains("is required")
        || m.contains("unsupported")
        || m.contains("invalid ")
        || m.contains("unknown oid")
        || m.contains("key not found")
        || m.contains("already consumed")
        || m.contains("too large")
        || m.contains("cmp_shim_invalid_argument")
}

fn is_resource_exhausted_crypto(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("resource_exhausted") || m.contains("memory allocation failed")
}

#[cfg(test)]
mod tests {
    use super::map_crypto_err;
    use tonic::Code;

    #[test]
    fn map_crypto_err_maps_cmp_shim_invalid_argument() {
        let err = anyhow::anyhow!("CMP_SHIM_INVALID_ARGUMENT(build_pki_message): bad der");
        let status = map_crypto_err(err);
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[test]
    fn map_crypto_err_maps_cmp_shim_resource_exhausted() {
        let err = anyhow::anyhow!(
            "CMP_SHIM_RESOURCE_EXHAUSTED(build_pki_message): memory allocation failed"
        );
        let status = map_crypto_err(err);
        assert_eq!(status.code(), Code::ResourceExhausted);
    }
}
