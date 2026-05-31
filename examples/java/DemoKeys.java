package com.cryptooffload.examples;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

/** 演示用 RSA-2048 密钥（仅示例，勿用于生产）。本地 CPU 运算，与 Offload RPC 无关。 */
final class DemoKeys {
    private DemoKeys() {}

    static byte[] privateKeyPem() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        PrivateKey key = gen.generateKeyPair().getPrivate();
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded());
        return ("-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n").getBytes();
    }
}
