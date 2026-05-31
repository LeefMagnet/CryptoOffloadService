//! OpenSSL 3 legacy provider（3DES 等算法，CMS/SCEP 解密可能需要）。

use std::sync::Once;

static INIT: Once = Once::new();

#[cfg(ossl300)]
static LEGACY_LOADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// OpenSSL 3 下 legacy provider 是否已成功加载（3DES EnvelopedData 依赖此项）。
#[cfg(ossl300)]
pub fn legacy_provider_loaded() -> bool {
    init();
    LEGACY_LOADED.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(not(ossl300))]
pub fn legacy_provider_loaded() -> bool {
    true
}

#[cfg(ossl300)]
pub fn init() {
    INIT.call_once(|| {
        use openssl::provider::Provider;
        Provider::try_load(None, "default", true).ok();
        if Provider::try_load(None, "legacy", true).is_ok() {
            LEGACY_LOADED.store(true, std::sync::atomic::Ordering::Relaxed);
        } else {
            eprintln!(
                "WARN: openssl legacy provider not loaded — SCEP/CMS 3DES EnvelopedData \
                 will fail (install openssl-provider-legacy on Debian/Ubuntu)"
            );
        }
        crate::scep_certrep::init_scep_oids();
    });
}

#[cfg(not(ossl300))]
pub fn init() {
    INIT.call_once(|| {
        crate::scep_certrep::init_scep_oids();
    });
}
