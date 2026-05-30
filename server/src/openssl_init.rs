//! OpenSSL 3 legacy provider（3DES 等算法，CMS 解密可能需要）。

use std::sync::Once;

static INIT: Once = Once::new();

#[cfg(ossl300)]
pub fn init() {
    INIT.call_once(|| {
        use openssl::provider::Provider;
        Provider::try_load(None, "default", true).ok();
        if Provider::try_load(None, "legacy", true).is_err() {
            eprintln!("WARN: openssl legacy provider not loaded");
        }
    });
}

#[cfg(not(ossl300))]
pub fn init() {
    INIT.call_once(|| {});
}
