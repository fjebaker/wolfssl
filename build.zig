const std = @import("std");

const CompileError = error{ArchitectureNotSupported};

fn createLibWolfSSL(
    b: *std.Build,
    is_shared: bool,
    target: std.zig.CrossTarget,
    optimize: std.builtin.Mode,
) *std.build.CompileStep {
    const lib = if (is_shared)
        b.addSharedLibrary(.{
            .name = "wolfssl",
            .target = target,
            .optimize = optimize,
            .version = .{ .major = 5, .minor = 6, .patch = 3 },
        })
    else
        b.addStaticLibrary(.{
            .name = "wolfssl",
            .target = target,
            .optimize = optimize,
        });

    lib.addIncludePath(std.build.LazyPath.relative("."));
    addSourceFile(lib);
    lib.linkLibC();
    // include headers in the build products
    lib.installHeadersDirectory("wolfssl", "wolfssl");
    return lib;
}

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const is_shared = b.option(bool, "shared", "Build wolfssl as a shared library.") orelse false;
    const debug = b.option(bool, "debug", "Enable debug logging.") orelse false;

    const lib = createLibWolfSSL(b, is_shared, target, optimize);
    defineMacros(lib, debug);
    b.installArtifact(lib);

    const test_exe = b.addExecutable(.{
        .name = "testsuite",
        .target = target,
        .optimize = optimize,
    });
    test_exe.addIncludePath(std.build.LazyPath.relative("."));
    test_exe.addCSourceFiles(&test_sources, &test_flags);

    test_exe.linkLibrary(lib);

    const run_test_step = b.addRunArtifact(test_exe);
    const run_tests = b.step("test", "Run tests");
    run_tests.dependOn(&run_test_step.step);
}

fn defineMacros(
    lib: *std.build.CompileStep,
    debug: bool,
) void {
    lib.defineCMacro("BUILD_GCM", null);
    lib.defineCMacro("ECC_TIMING_RESISTANT", null);
    lib.defineCMacro("TFM_TIMING_RESISTANT", null);
    lib.defineCMacro("HAVE_AESCCM", null);
    lib.defineCMacro("HAVE_ALPN", null);
    lib.defineCMacro("HAVE_CHACHA", null);
    lib.defineCMacro("HAVE_ECC", null);
    lib.defineCMacro("HAVE_FFDHE_2048", null);
    lib.defineCMacro("HAVE_FFDHE_3072", null);
    lib.defineCMacro("HAVE_FFDHE_4096", null);
    lib.defineCMacro("HAVE_FFDHE_6144", null);
    lib.defineCMacro("HAVE_FFDHE_8192", null);
    lib.defineCMacro("HAVE_HKDF", null);
    lib.defineCMacro("HAVE_MAX_FRAGMENT", null);
    lib.defineCMacro("HAVE_ONE_TIME_AUTH", null);
    lib.defineCMacro("HAVE_POLY1305", null);
    lib.defineCMacro("HAVE_PTHREAD", null);
    lib.defineCMacro("HAVE_SESSION_TICKET", null);
    lib.defineCMacro("HAVE_SNI", null);
    lib.defineCMacro("HAVE_SYS_TIME_H", null);
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", null);
    lib.defineCMacro("HAVE_TRUNCATED_HMAC", null);
    lib.defineCMacro("HAVE_TRUSTED_CA", null);
    // lib.defineCMacro("NO_INLINE", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509_SMALL", null);
    lib.defineCMacro("SESSION_CERTS", null);
    lib.defineCMacro("SESSION_INDEX", null);
    lib.defineCMacro("TFM_TIMING_RESISTANT", null);
    lib.defineCMacro("WC_RSA_BLINDING", null);
    lib.defineCMacro("WC_RSA_PSS", null);
    // tls 1.3
    lib.defineCMacro("HAVE_FFDHE_2048", null);
    lib.defineCMacro("HAVE_HKDF", null);
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", null);
    lib.defineCMacro("WC_RSA_PSS", null);
    lib.defineCMacro("WOLFSSL_TLS13", null);

    // lib.defineCMacro("HAVE_DH", null);
    // lib.defineCMacro("WOLFSSL_STATIC_DH", null);
    // lib.defineCMacro("WOLFSSL_STATIC_RSA", null);
    // on by default
    lib.defineCMacro("HAVE_SUPPORTED_CURVES", null);
    lib.defineCMacro("HAVE_EXTENDED_MASTER", null);
    lib.defineCMacro("HAVE_ENCRYPT_THEN_MAC", null);
    lib.defineCMacro("HAVE_ONE_TIME_AUTH", null);
    // lib.defineCMacro("WOLFSSL_ASN_PRINT", null);
    // lib.defineCMacro("WOLFSSL_POST_HANDSHAKE_AUTH", null);
    // lib.defineCMacro("WOLFSSL_SEND_HRR_COOKIE", null);
    // lib.defineCMacro("WOLFSSL_SHA224", null);
    // lib.defineCMacro("WOLFSSL_SHA384", null);
    // lib.defineCMacro("WOLFSSL_SHA3", null);
    // lib.defineCMacro("WOLFSSL_SHA512", null);

    if (debug) {
        lib.defineCMacro("DEBUG_WOLFSSL", null);
        lib.defineCMacro("DEBUG", "1");
        lib.linkSystemLibrary("asan");
    }
}

fn addSourceFile(lib: *std.build.CompileStep) void {
    lib.addCSourceFiles(&wolfssl_sources, &wolfssl_flags);
    lib.addCSourceFiles(&wolfcrypt_sources, &wolfcrypt_flags);
}

const test_flags = [_][]const u8{
    "-std=c99",
};

const wolfssl_flags = [_][]const u8{
    // "-std=c89",
    "-Wno-int-conversion",
};

const wolfcrypt_flags = [_][]const u8{
    // "-std=c89",
    "-Wno-int-conversion",
};

const test_sources = [_][]const u8{
    "wolfcrypt/test/test.c",
    // "examples/client/client.c",
    // "examples/echoclient/echoclient.c",
    // "examples/echoserver/echoserver.c",
    // "examples/server/server.c",
    // "testsuite/testsuite.c",
    // "testsuite/testsuite.c",
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
    "src/ssl_misc.c",
    "src/tls13.c",
    "src/tls.c",
    "src/wolfio.c",
    "src/x509.c",
    "src/x509_str.c",
    // "src/internal.c",
    // "src/keys.c",
    // "src/ssl.c",
    // "src/tls13.c",
    // "src/tls.c",
    // "src/wolfio.c",
};

const wolfcrypt_sources = [_][]const u8{
    "wolfcrypt/src/aes.c",
    "wolfcrypt/src/asn.c",
    "wolfcrypt/src/chacha20_poly1305.c",
    "wolfcrypt/src/chacha.c",
    "wolfcrypt/src/coding.c",
    "wolfcrypt/src/cpuid.c",
    "wolfcrypt/src/des3.c",
    "wolfcrypt/src/dh.c",
    "wolfcrypt/src/dsa.c",
    "wolfcrypt/src/ecc.c",
    "wolfcrypt/src/error.c",
    "wolfcrypt/src/hash.c",
    "wolfcrypt/src/hmac.c",
    "wolfcrypt/src/kdf.c",
    "wolfcrypt/src/logging.c",
    "wolfcrypt/src/md5.c",
    "wolfcrypt/src/memory.c",
    "wolfcrypt/src/pkcs12.c",
    "wolfcrypt/src/poly1305.c",
    "wolfcrypt/src/pwdbased.c",
    "wolfcrypt/src/random.c",
    "wolfcrypt/src/rsa.c",
    "wolfcrypt/src/sha256.c",
    "wolfcrypt/src/sha3.c",
    "wolfcrypt/src/sha512.c",
    "wolfcrypt/src/sha.c",
    "wolfcrypt/src/signature.c",
    "wolfcrypt/src/sp_int.c",
    "wolfcrypt/src/wc_encrypt.c",
    "wolfcrypt/src/wc_port.c",
    "wolfcrypt/src/wolfmath.c",
};

const old_wolfcrypt_sources = [_][]const u8{
    "wolfcrypt/src/aes.c",
    "wolfcrypt/src/arc4.c",
    "wolfcrypt/src/asm.c",
    "wolfcrypt/src/asn.c",
    "wolfcrypt/src/async.c",
    "wolfcrypt/src/blake2b.c",
    "wolfcrypt/src/blake2s.c",
    "wolfcrypt/src/camellia.c",
    "wolfcrypt/src/chacha20_poly1305.c",
    "wolfcrypt/src/chacha.c",
    "wolfcrypt/src/cmac.c",
    "wolfcrypt/src/coding.c",
    "wolfcrypt/src/compress.c",
    "wolfcrypt/src/cpuid.c",
    "wolfcrypt/src/cryptocb.c",
    "wolfcrypt/src/curve25519.c",
    "wolfcrypt/src/curve448.c",
    "wolfcrypt/src/des3.c",
    "wolfcrypt/src/dh.c",
    "wolfcrypt/src/dilithium.c",
    "wolfcrypt/src/dsa.c",
    "wolfcrypt/src/ecc.c",
    "wolfcrypt/src/ecc_fp.c",
    "wolfcrypt/src/eccsi.c",
    "wolfcrypt/src/ed25519.c",
    "wolfcrypt/src/ed448.c",
    "wolfcrypt/src/error.c",
    "wolfcrypt/src/evp.c",
    "wolfcrypt/src/ext_kyber.c",
    "wolfcrypt/src/falcon.c",
    "wolfcrypt/src/fe_448.c",
    "wolfcrypt/src/fe_low_mem.c",
    "wolfcrypt/src/fe_operations.c",
    "wolfcrypt/src/fips.c",
    "wolfcrypt/src/fips_test.c",
    "wolfcrypt/src/ge_448.c",
    "wolfcrypt/src/ge_low_mem.c",
    "wolfcrypt/src/ge_operations.c",
    "wolfcrypt/src/hash.c",
    "wolfcrypt/src/hmac.c",
    "wolfcrypt/src/hpke.c",
    "wolfcrypt/src/integer.c",
    "wolfcrypt/src/kdf.c",
    "wolfcrypt/src/logging.c",
    "wolfcrypt/src/md2.c",
    "wolfcrypt/src/md4.c",
    "wolfcrypt/src/md5.c",
    "wolfcrypt/src/memory.c",
    "wolfcrypt/src/misc.c",
    "wolfcrypt/src/pkcs12.c",
    "wolfcrypt/src/pkcs7.c",
    "wolfcrypt/src/poly1305.c",
    // "wolfcrypt/src/port/af_alg/afalg_aes.c",
    // "wolfcrypt/src/port/af_alg/afalg_hash.c",
    // "wolfcrypt/src/port/af_alg/wc_afalg.c",
    // "wolfcrypt/src/port/arm/armv8-32-curve25519_c.c",
    // "wolfcrypt/src/port/arm/armv8-32-sha256-asm_c.c",
    // "wolfcrypt/src/port/arm/armv8-32-sha512-asm_c.c",
    // "wolfcrypt/src/port/arm/armv8-aes.c",
    // "wolfcrypt/src/port/arm/armv8-chacha.c",
    // "wolfcrypt/src/port/arm/armv8-curve25519_c.c",
    // "wolfcrypt/src/port/arm/armv8-poly1305.c",
    // "wolfcrypt/src/port/arm/armv8-sha256.c",
    // "wolfcrypt/src/port/arm/armv8-sha3-asm_c.c",
    // "wolfcrypt/src/port/arm/armv8-sha512-asm_c.c",
    // "wolfcrypt/src/port/arm/armv8-sha512.c",
    // "wolfcrypt/src/port/arm/cryptoCell.c",
    // "wolfcrypt/src/port/arm/cryptoCellHash.c",
    // "wolfcrypt/src/port/atmel/atmel.c",
    // "wolfcrypt/src/port/caam/caam_aes.c",
    // "wolfcrypt/src/port/caam/caam_driver.c",
    // "wolfcrypt/src/port/caam/caam_error.c",
    // "wolfcrypt/src/port/caam/caam_integrity.c",
    // "wolfcrypt/src/port/caam/caam_qnx.c",
    // "wolfcrypt/src/port/caam/caam_sha.c",
    // "wolfcrypt/src/port/caam/wolfcaam_aes.c",
    // "wolfcrypt/src/port/caam/wolfcaam_cmac.c",
    // "wolfcrypt/src/port/caam/wolfcaam_ecdsa.c",
    // "wolfcrypt/src/port/caam/wolfcaam_fsl_nxp.c",
    // "wolfcrypt/src/port/caam/wolfcaam_hash.c",
    // "wolfcrypt/src/port/caam/wolfcaam_hmac.c",
    // "wolfcrypt/src/port/caam/wolfcaam_init.c",
    // "wolfcrypt/src/port/caam/wolfcaam_qnx.c",
    // "wolfcrypt/src/port/caam/wolfcaam_rsa.c",
    // "wolfcrypt/src/port/caam/wolfcaam_seco.c",
    // "wolfcrypt/src/port/caam/wolfcaam_x25519.c",
    // "wolfcrypt/src/port/cavium/cavium_nitrox.c",
    // "wolfcrypt/src/port/cavium/cavium_octeon_sync.c",
    // "wolfcrypt/src/port/cypress/psoc6_crypto.c",
    // "wolfcrypt/src/port/devcrypto/devcrypto_aes.c",
    // "wolfcrypt/src/port/devcrypto/devcrypto_ecdsa.c",
    // "wolfcrypt/src/port/devcrypto/devcrypto_hash.c",
    // "wolfcrypt/src/port/devcrypto/devcrypto_hmac.c",
    // "wolfcrypt/src/port/devcrypto/devcrypto_rsa.c",
    // "wolfcrypt/src/port/devcrypto/devcrypto_x25519.c",
    // "wolfcrypt/src/port/devcrypto/wc_devcrypto.c",
    // "wolfcrypt/src/port/Espressif/esp32_aes.c",
    // "wolfcrypt/src/port/Espressif/esp32_mp.c",
    // "wolfcrypt/src/port/Espressif/esp32_sha.c",
    // "wolfcrypt/src/port/Espressif/esp32_util.c",
    // "wolfcrypt/src/port/intel/quickassist.c",
    // "wolfcrypt/src/port/intel/quickassist_mem.c",
    // "wolfcrypt/src/port/intel/quickassist_sync.c",
    // "wolfcrypt/src/port/iotsafe/iotsafe.c",
    // "wolfcrypt/src/port/kcapi/kcapi_aes.c",
    // "wolfcrypt/src/port/kcapi/kcapi_dh.c",
    // "wolfcrypt/src/port/kcapi/kcapi_ecc.c",
    // "wolfcrypt/src/port/kcapi/kcapi_hash.c",
    // "wolfcrypt/src/port/kcapi/kcapi_hmac.c",
    // "wolfcrypt/src/port/kcapi/kcapi_rsa.c",
    // "wolfcrypt/src/port/maxim/maxq10xx.c",
    // "wolfcrypt/src/port/mynewt/mynewt_port.c",
    // "wolfcrypt/src/port/nrf51.c",
    // "wolfcrypt/src/port/nxp/dcp_port.c",
    // "wolfcrypt/src/port/nxp/ksdk_port.c",
    // "wolfcrypt/src/port/nxp/se050_port.c",
    // "wolfcrypt/src/port/pic32/pic32mz-crypt.c",
    // "wolfcrypt/src/port/psa/psa_aes.c",
    // "wolfcrypt/src/port/psa/psa.c",
    // "wolfcrypt/src/port/psa/psa_hash.c",
    // "wolfcrypt/src/port/psa/psa_pkcbs.c",
    // "wolfcrypt/src/port/Renesas/renesas_common.c",
    // "wolfcrypt/src/port/Renesas/renesas_rx64_hw_sha.c",
    // "wolfcrypt/src/port/Renesas/renesas_rx64_hw_util.c",
    // "wolfcrypt/src/port/Renesas/renesas_sce_aes.c",
    // "wolfcrypt/src/port/Renesas/renesas_sce_rsa.c",
    // "wolfcrypt/src/port/Renesas/renesas_sce_sha.c",
    // "wolfcrypt/src/port/Renesas/renesas_sce_util.c",
    // "wolfcrypt/src/port/Renesas/renesas_tsip_aes.c",
    // "wolfcrypt/src/port/Renesas/renesas_tsip_sha.c",
    // "wolfcrypt/src/port/Renesas/renesas_tsip_util.c",
    // "wolfcrypt/src/port/silabs/silabs_aes.c",
    // "wolfcrypt/src/port/silabs/silabs_ecc.c",
    // "wolfcrypt/src/port/silabs/silabs_hash.c",
    // "wolfcrypt/src/port/silabs/silabs_random.c",
    // "wolfcrypt/src/port/st/stm32.c",
    // "wolfcrypt/src/port/st/stsafe.c",
    // "wolfcrypt/src/port/ti/ti-aes.c",
    // "wolfcrypt/src/port/ti/ti-ccm.c",
    // "wolfcrypt/src/port/ti/ti-des3.c",
    // "wolfcrypt/src/port/ti/ti-hash.c",
    // "wolfcrypt/src/port/xilinx/xil-aesgcm.c",
    // "wolfcrypt/src/port/xilinx/xil-sha3.c",
    // "wolfcrypt/src/port/xilinx/xil-versal-glue.c",
    // "wolfcrypt/src/port/xilinx/xil-versal-trng.c",
    "wolfcrypt/src/pwdbased.c",
    "wolfcrypt/src/random.c",
    "wolfcrypt/src/rc2.c",
    "wolfcrypt/src/ripemd.c",
    "wolfcrypt/src/rsa.c",
    "wolfcrypt/src/sakke.c",
    "wolfcrypt/src/selftest.c",
    "wolfcrypt/src/sha256.c",
    "wolfcrypt/src/sha3.c",
    "wolfcrypt/src/sha512.c",
    "wolfcrypt/src/sha.c",
    "wolfcrypt/src/signature.c",
    "wolfcrypt/src/siphash.c",
    "wolfcrypt/src/sp_arm32.c",
    "wolfcrypt/src/sp_arm64.c",
    "wolfcrypt/src/sp_armthumb.c",
    "wolfcrypt/src/sp_c32.c",
    "wolfcrypt/src/sp_c64.c",
    "wolfcrypt/src/sp_cortexm.c",
    "wolfcrypt/src/sp_dsp32.c",
    "wolfcrypt/src/sphincs.c",
    "wolfcrypt/src/sp_int.c",
    "wolfcrypt/src/sp_x86_64.c",
    "wolfcrypt/src/srp.c",
    "wolfcrypt/src/tfm.c",
    "wolfcrypt/src/wc_dsp.c",
    "wolfcrypt/src/wc_encrypt.c",
    "wolfcrypt/src/wc_kyber.c",
    "wolfcrypt/src/wc_kyber_poly.c",
    "wolfcrypt/src/wc_pkcs11.c",
    "wolfcrypt/src/wc_port.c",
    "wolfcrypt/src/wolfcrypt_first.c",
    "wolfcrypt/src/wolfcrypt_last.c",
    "wolfcrypt/src/wolfevent.c",
    "wolfcrypt/src/wolfmath.c",
};
