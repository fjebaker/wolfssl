const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const static_lib = b.addStaticLibrary(.{
        .name = "wolfssl",
        .target = target,
        .optimize = optimize,
    });

    static_lib.addIncludePath(std.build.LazyPath.relative("."));
    addSourceFile(static_lib);
    defineMacros(static_lib);
    static_lib.linkLibC();
    // include headers in the build products
    static_lib.installHeadersDirectory("wolfssl", "wolfssl");

    b.installArtifact(static_lib);
}

fn defineMacros(lib: *std.build.CompileStep) void {
    lib.defineCMacro("TFM_TIMING_RESISTANT", null);
    lib.defineCMacro("ECC_TIMING_RESISTANT", null);
    lib.defineCMacro("WC_RSA_BLINDING", null);
    lib.defineCMacro("HAVE_PTHREAD", null);
    lib.defineCMacro("NO_INLINE", null);
    lib.defineCMacro("WOLFSSL_TLS13", null);
    lib.defineCMacro("WC_RSA_PSS", null);
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", null);
    lib.defineCMacro("HAVE_SNI", null);
    lib.defineCMacro("HAVE_MAX_FRAGMENT", null);
    lib.defineCMacro("HAVE_TRUNCATED_HMAC", null);
    lib.defineCMacro("HAVE_ALPN", null);
    lib.defineCMacro("HAVE_TRUSTED_CA", null);
    lib.defineCMacro("HAVE_HKDF", null);
    lib.defineCMacro("BUILD_GCM", null);
    lib.defineCMacro("HAVE_AESCCM", null);
    lib.defineCMacro("HAVE_SESSION_TICKET", null);
    lib.defineCMacro("HAVE_CHACHA", null);
    lib.defineCMacro("HAVE_POLY1305", null);
    lib.defineCMacro("HAVE_ECC", null);
    lib.defineCMacro("HAVE_FFDHE_2048", null);
    lib.defineCMacro("HAVE_FFDHE_3072", null);
    lib.defineCMacro("HAVE_FFDHE_4096", null);
    lib.defineCMacro("HAVE_FFDHE_6144", null);
    lib.defineCMacro("HAVE_FFDHE_8192", null);
    lib.defineCMacro("HAVE_ONE_TIME_AUTH", null);
    lib.defineCMacro("HAVE_SYS_TIME_H", null);
    lib.defineCMacro("SESSION_INDEX", null);
    lib.defineCMacro("SESSION_CERTS", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509_SMALL", null);
}

fn addSourceFile(lib: *std.build.CompileStep) void {
    lib.addCSourceFiles(&wolfssl_sources, &wolfssl_flags);
    lib.addCSourceFiles(&wolfcrypt_sources, &wolfcrypt_flags);
}

const wolfssl_flags = [_][]const u8{
    "-std=c89", "-Wno-int-conversion",
};

const wolfcrypt_flags = [_][]const u8{
    "-std=c89", "-Wno-int-conversion",
};

const wolfssl_sources = [_][]const u8{
    "src/bio.c",
    "src/conf.c",
    "src/crl.c",
    "src/dtls13.c",
    "src/dtls.c",
    "src/internal.c",
    "src/keys.c",
    "src/ocsp.c",
    "src/pk.c",
    "src/quic.c",
    "src/sniffer.c",
    "src/ssl_asn1.c",
    "src/ssl_bn.c",
    "src/ssl.c",
    "src/ssl_certman.c",
    "src/ssl_misc.c",
    "src/tls13.c",
    "src/tls.c",
    "src/wolfio.c",
    "src/x509.c",
    "src/x509_str.c",
};

const wolfcrypt_sources = [_][]const u8{
    "wolfcrypt/src/coding.c",
    "wolfcrypt/src/wc_pkcs11.c",
    "wolfcrypt/src/md5.c",
    "wolfcrypt/src/dh.c",
    "wolfcrypt/src/sm4.c",
    "wolfcrypt/src/ed448.c",
    "wolfcrypt/src/dsa.c",
    "wolfcrypt/src/sp_dsp32.c",
    "wolfcrypt/src/chacha20_poly1305.c",
    "wolfcrypt/src/wolfevent.c",
    "wolfcrypt/src/evp.c",
    "wolfcrypt/src/wc_lms.c",
    "wolfcrypt/src/pkcs7.c",
    "wolfcrypt/src/wc_kyber_poly.c",
    "wolfcrypt/src/sp_c64.c",
    "wolfcrypt/src/poly1305.c",
    "wolfcrypt/src/sm3.c",
    "wolfcrypt/src/hmac.c",
    "wolfcrypt/src/random.c",
    "wolfcrypt/src/dilithium.c",
    "wolfcrypt/src/srp.c",
    "wolfcrypt/src/blake2b.c",
    "wolfcrypt/src/wc_kyber.c",
    "wolfcrypt/src/sp_c32.c",
    "wolfcrypt/src/chacha.c",
    "wolfcrypt/src/falcon.c",
    "wolfcrypt/src/tfm.c",
    "wolfcrypt/src/asm.c",
    "wolfcrypt/src/curve25519.c",
    "wolfcrypt/src/md2.c",
    "wolfcrypt/src/hash.c",
    "wolfcrypt/src/asn.c",
    "wolfcrypt/src/sphincs.c",
    "wolfcrypt/src/wc_encrypt.c",
    "wolfcrypt/src/sp_x86_64.c",
    "wolfcrypt/src/sp_armthumb.c",
    "wolfcrypt/src/fe_low_mem.c",
    "wolfcrypt/src/misc.c",
    "wolfcrypt/src/aes.c",
    "wolfcrypt/src/rsa.c",
    "wolfcrypt/src/sakke.c",
    "wolfcrypt/src/md4.c",
    "wolfcrypt/src/blake2s.c",
    "wolfcrypt/src/siphash.c",
    "wolfcrypt/src/cpuid.c",
    "wolfcrypt/src/rc2.c",
    "wolfcrypt/src/sp_int.c",
    "wolfcrypt/src/memory.c",
    "wolfcrypt/src/hpke.c",
    "wolfcrypt/src/pkcs12.c",
    "wolfcrypt/src/sha.c",
    "wolfcrypt/src/sha512.c",
    "wolfcrypt/src/ripemd.c",
    "wolfcrypt/src/cmac.c",
    "wolfcrypt/src/signature.c",
    "wolfcrypt/src/sp_arm32.c",
    "wolfcrypt/src/arc4.c",
    "wolfcrypt/src/ext_kyber.c",
    "wolfcrypt/src/curve448.c",
    "wolfcrypt/src/ge_448.c",
    "wolfcrypt/src/port/nxp/dcp_port.c",
    "wolfcrypt/src/port/nxp/ksdk_port.c",
    "wolfcrypt/src/port/nxp/se050_port.c",
    "wolfcrypt/src/port/pic32/pic32mz-crypt.c",
    "wolfcrypt/src/port/aria/aria-crypt.c",
    "wolfcrypt/src/port/aria/aria-cryptocb.c",
    "wolfcrypt/src/port/xilinx/xil-versal-glue.c",
    "wolfcrypt/src/port/xilinx/xil-aesgcm.c",
    "wolfcrypt/src/port/xilinx/xil-versal-trng.c",
    "wolfcrypt/src/port/xilinx/xil-sha3.c",
    "wolfcrypt/src/port/psa/psa.c",
    "wolfcrypt/src/port/psa/psa_hash.c",
    "wolfcrypt/src/port/psa/psa_aes.c",
    "wolfcrypt/src/port/psa/psa_pkcbs.c",
    "wolfcrypt/src/port/nrf51.c",
    "wolfcrypt/src/port/Espressif/esp32_aes.c",
    "wolfcrypt/src/port/Espressif/esp32_mp.c",
    "wolfcrypt/src/port/Espressif/esp32_util.c",
    "wolfcrypt/src/port/Espressif/esp32_sha.c",
    "wolfcrypt/src/port/maxim/maxq10xx.c",
    "wolfcrypt/src/port/intel/quickassist_sync.c",
    "wolfcrypt/src/port/caam/caam_integrity.c",
    "wolfcrypt/src/port/caam/wolfcaam_x25519.c",
    "wolfcrypt/src/port/caam/wolfcaam_qnx.c",
    "wolfcrypt/src/port/caam/caam_error.c",
    "wolfcrypt/src/port/caam/caam_qnx.c",
    "wolfcrypt/src/port/caam/wolfcaam_ecdsa.c",
    "wolfcrypt/src/port/caam/wolfcaam_hash.c",
    "wolfcrypt/src/port/caam/wolfcaam_hmac.c",
    "wolfcrypt/src/port/caam/caam_aes.c",
    "wolfcrypt/src/port/caam/wolfcaam_init.c",
    "wolfcrypt/src/port/caam/wolfcaam_seco.c",
    "wolfcrypt/src/port/caam/wolfcaam_aes.c",
    "wolfcrypt/src/port/caam/wolfcaam_fsl_nxp.c",
    "wolfcrypt/src/port/caam/caam_sha.c",
    "wolfcrypt/src/port/caam/wolfcaam_cmac.c",
    "wolfcrypt/src/port/caam/caam_driver.c",
    "wolfcrypt/src/port/caam/wolfcaam_rsa.c",
    "wolfcrypt/src/port/atmel/atmel.c",
    "wolfcrypt/src/port/ti/ti-ccm.c",
    "wolfcrypt/src/port/ti/ti-aes.c",
    "wolfcrypt/src/port/ti/ti-hash.c",
    "wolfcrypt/src/port/ti/ti-des3.c",
    "wolfcrypt/src/port/kcapi/kcapi_ecc.c",
    "wolfcrypt/src/port/kcapi/kcapi_dh.c",
    "wolfcrypt/src/port/kcapi/kcapi_rsa.c",
    "wolfcrypt/src/port/kcapi/kcapi_aes.c",
    "wolfcrypt/src/port/kcapi/kcapi_hash.c",
    "wolfcrypt/src/port/kcapi/kcapi_hmac.c",
    "wolfcrypt/src/port/devcrypto/devcrypto_hash.c",
    "wolfcrypt/src/port/devcrypto/devcrypto_aes.c",
    "wolfcrypt/src/port/devcrypto/devcrypto_ecdsa.c",
    "wolfcrypt/src/port/devcrypto/devcrypto_x25519.c",
    "wolfcrypt/src/port/devcrypto/wc_devcrypto.c",
    "wolfcrypt/src/port/devcrypto/devcrypto_rsa.c",
    "wolfcrypt/src/port/devcrypto/devcrypto_hmac.c",
    "wolfcrypt/src/port/cypress/psoc6_crypto.c",
    "wolfcrypt/src/port/st/stsafe.c",
    "wolfcrypt/src/port/st/stm32.c",
    "wolfcrypt/src/port/Renesas/renesas_tsip_aes.c",
    "wolfcrypt/src/port/Renesas/renesas_tsip_util.c",
    "wolfcrypt/src/port/Renesas/renesas_common.c",
    "wolfcrypt/src/port/Renesas/renesas_rx64_hw_sha.c",
    "wolfcrypt/src/port/Renesas/renesas_tsip_sha.c",
    "wolfcrypt/src/port/Renesas/renesas_tsip_rsa.c",
    "wolfcrypt/src/port/Renesas/renesas_fspsm_aes.c",
    "wolfcrypt/src/port/Renesas/renesas_fspsm_rsa.c",
    "wolfcrypt/src/port/Renesas/renesas_rx64_hw_util.c",
    "wolfcrypt/src/port/Renesas/renesas_fspsm_util.c",
    "wolfcrypt/src/port/Renesas/renesas_fspsm_sha.c",
    "wolfcrypt/src/port/mynewt/mynewt_port.c",
    "wolfcrypt/src/port/arm/armv8-32-aes-asm_c.c",
    "wolfcrypt/src/port/arm/thumb2-sha512-asm_c.c",
    "wolfcrypt/src/port/arm/armv8-sha256.c",
    "wolfcrypt/src/port/arm/armv8-sha512-asm_c.c",
    "wolfcrypt/src/port/arm/armv8-32-sha256-asm_c.c",
    "wolfcrypt/src/port/arm/armv8-poly1305.c",
    "wolfcrypt/src/port/arm/armv8-32-curve25519_c.c",
    "wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c",
    "wolfcrypt/src/port/arm/armv8-chacha.c",
    "wolfcrypt/src/port/arm/armv8-curve25519_c.c",
    "wolfcrypt/src/port/arm/armv8-aes.c",
    "wolfcrypt/src/port/arm/cryptoCellHash.c",
    "wolfcrypt/src/port/arm/cryptoCell.c",
    "wolfcrypt/src/port/arm/thumb2-curve25519_c.c",
    "wolfcrypt/src/port/arm/armv8-sha3-asm_c.c",
    "wolfcrypt/src/port/arm/armv8-sha512.c",
    "wolfcrypt/src/port/arm/armv8-32-sha512-asm_c.c",
    "wolfcrypt/src/port/silabs/silabs_random.c",
    "wolfcrypt/src/port/silabs/silabs_hash.c",
    "wolfcrypt/src/port/silabs/silabs_aes.c",
    "wolfcrypt/src/port/silabs/silabs_ecc.c",
    "wolfcrypt/src/port/af_alg/afalg_aes.c",
    "wolfcrypt/src/port/af_alg/afalg_hash.c",
    "wolfcrypt/src/port/af_alg/wc_afalg.c",
    "wolfcrypt/src/port/iotsafe/iotsafe.c",
    "wolfcrypt/src/port/cavium/cavium_octeon_sync.c",
    "wolfcrypt/src/ecc.c",
    "wolfcrypt/src/ge_low_mem.c",
    "wolfcrypt/src/logging.c",
    "wolfcrypt/src/wc_port.c",
    "wolfcrypt/src/wolfmath.c",
    "wolfcrypt/src/ext_lms.c",
    "wolfcrypt/src/integer.c",
    "wolfcrypt/src/cryptocb.c",
    "wolfcrypt/src/ge_operations.c",
    "wolfcrypt/src/fe_448.c",
    "wolfcrypt/src/sm2.c",
    "wolfcrypt/src/compress.c",
    "wolfcrypt/src/eccsi.c",
    "wolfcrypt/src/sha3.c",
    "wolfcrypt/src/kdf.c",
    "wolfcrypt/src/sha256.c",
    "wolfcrypt/src/sp_cortexm.c",
    "wolfcrypt/src/camellia.c",
    "wolfcrypt/src/error.c",
    "wolfcrypt/src/wc_dsp.c",
    "wolfcrypt/src/des3.c",
    "wolfcrypt/src/pwdbased.c",
    "wolfcrypt/src/ed25519.c",
    "wolfcrypt/src/sp_arm64.c",
    "wolfcrypt/src/ecc_fp.c",
    "wolfcrypt/src/fe_operations.c",
};
