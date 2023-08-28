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

    const is_shared = b.option(bool, "shared", "Build wolfssl as a shared library.") orelse true;
    const debug = b.option(bool, "debug", "Enable debug logging.") orelse false;
    const with_tests = b.option(bool, "tests", "Build test suite as executable.") orelse false;

    const lib = createLibWolfSSL(b, is_shared, target, optimize);
    try defineMacros(lib, debug, target);
    b.installArtifact(lib);

    if (with_tests) {
        const test_exe = b.addExecutable(.{
            .name = "testsuite",
            .target = target,
            .optimize = optimize,
        });
        test_exe.addIncludePath(std.build.LazyPath.relative("."));
        test_exe.addCSourceFiles(&test_sources, &test_flags);
        const test_lib = createLibWolfSSL(b, is_shared, target, optimize);

        try defineTestMacros(test_lib, target);
        test_exe.linkLibrary(test_lib);

        b.installArtifact(test_exe);
    }
}

fn defineTestMacros(lib: *std.build.CompileStep, target: std.zig.CrossTarget) !void {
    lib.defineCMacro("ECC_SHAMIR", null);
    lib.defineCMacro("ECC_TIMING_RESISTANT", null);
    lib.defineCMacro("ERROR_QUEUE_PER_THREAD", null);
    lib.defineCMacro("GCM_TABLE_4BIT", null);

    lib.defineCMacro("HAVE_AESGCM", null);
    lib.defineCMacro("HAVE_C___ATOMIC", "1");
    lib.defineCMacro("HAVE_CHACHA", null);
    lib.defineCMacro("HAVE_DH_DEFAULT_PARAMS", null);
    lib.defineCMacro("HAVE_ECC", null);
    lib.defineCMacro("HAVE_ENCRYPT_THEN_MAC", null);
    lib.defineCMacro("HAVE_EXTENDED_MASTER", null);
    lib.defineCMacro("HAVE_FFDHE_2048", null);
    lib.defineCMacro("HAVE_HASHDRBG", null);
    lib.defineCMacro("HAVE_HKDF", null);
    lib.defineCMacro("HAVE_POLY1305", null);
    lib.defineCMacro("HAVE_SERVER_RENEGOTIATION_INFO", null);
    lib.defineCMacro("HAVE_SNI", null);
    lib.defineCMacro("HAVE_SUPPORTED_CURVES", null);
    lib.defineCMacro("HAVE_THREAD_LS", null);
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", null);
    lib.defineCMacro("HAVE_WC_INTROSPECTION", null);

    std.fs.cwd().access("config.h", .{}) catch |err| {
        try std.io.getStdErr().writeAll(
            "config.h missing: run ./autogen.sh && configure first (only needed for tests)",
        );
        return err;
    };
    lib.defineCMacro("HAVE_CONFIG_H", null);

    lib.defineCMacro("NO_DES3", null);
    lib.defineCMacro("NO_DO178", null);
    lib.defineCMacro("NO_DSA", null);
    lib.defineCMacro("NO_INLINE", null);
    lib.defineCMacro("NO_MD4", null);
    lib.defineCMacro("NO_PSK", null);
    lib.defineCMacro("NO_RC4", null);

    lib.defineCMacro("TFM_ECC256", null);
    lib.defineCMacro("TFM_TIMING_RESISTANT", null);

    lib.defineCMacro("WC_NO_ASYNC_THREADING", null);
    lib.defineCMacro("WC_RSA_BLINDING", null);
    lib.defineCMacro("WC_RSA_PSS", null);

    lib.defineCMacro("WOLFSSL_ASN_PRINT", null);
    lib.defineCMacro("WOLFSSL_ASN_TEMPLATE", null);
    lib.defineCMacro("WOLFSSL_BASE64_ENCODE", null);
    lib.defineCMacro("WOLFSSL_HAVE_ATOMIC_H", null);
    lib.defineCMacro("WOLFSSL_NO_SHAKE128", null);
    lib.defineCMacro("WOLFSSL_NO_SHAKE256", null);
    lib.defineCMacro("WOLFSSL_PSS_LONG_SALT", null);
    lib.defineCMacro("WOLFSSL_SHA224", null);
    lib.defineCMacro("WOLFSSL_SHA384", null);
    lib.defineCMacro("WOLFSSL_SHA3", null);
    lib.defineCMacro("WOLFSSL_SHA512", null);
    lib.defineCMacro("WOLFSSL_SP_MATH_ALL", null);
    lib.defineCMacro("WOLFSSL_SYS_CA_CERTS", null);
    lib.defineCMacro("WOLFSSL_TLS13", null);
    lib.defineCMacro("WOLFSSL_USE_ALIGN", null);

    const arch = target.getCpuArch();
    switch (arch) {
        .x86_64 => {
            lib.defineCMacro("WOLFSSL_SP_X86_64", null);
            lib.defineCMacro("WOLFSSL_X86_64_BUILD", null);
        },
        .x86 => lib.defineCMacro("WOLFSSL_SP_X86", null),
        .aarch64 => {
            lib.defineCMacro("WOLFSSL_ARMASM", null);
            lib.defineCMacro("WOLFSSL_SP_ARM64_ASM", null);
        },
        else => |a| {
            std.debug.print("Architecture: {any}", .{a});
            return CompileError.ArchitectureNotSupported;
        },
    }
}

fn defineMacros(
    lib: *std.build.CompileStep,
    debug: bool,
    target: std.zig.CrossTarget,
) !void {
    lib.defineCMacro("BUILD_USER_RSA", "");
    lib.defineCMacro("HAVE_C___ATOMIC", "1");
    lib.defineCMacro("HAVE_DECL_ATEXIT", "1");
    lib.defineCMacro("HAVE_DECL_GETADDRINFO", "1");
    lib.defineCMacro("HAVE_DECL_GETHOSTBYNAME", "1");
    lib.defineCMacro("HAVE_DECL_GETTIMEOFDAY", "1");
    lib.defineCMacro("HAVE_DECL_GMTIME_R", "1");
    lib.defineCMacro("HAVE_DECL_GMTIME_S", "0");
    lib.defineCMacro("HAVE_DECL_INET_NTOA", "1");
    lib.defineCMacro("HAVE_DECL_MEMSET", "1");
    lib.defineCMacro("HAVE_DECL_SOCKET", "1");
    lib.defineCMacro("HAVE_DECL_STRFTIME", "1");
    lib.defineCMacro("HAVE_DLFCN_H", "1");
    lib.defineCMacro("HAVE_ERRNO_H", "1");
    lib.defineCMacro("HAVE_FCNTL_H", "1");
    lib.defineCMacro("HAVE_GETADDRINFO", "1");
    lib.defineCMacro("HAVE_GETHOSTBYNAME", "1");
    lib.defineCMacro("HAVE_GETTIMEOFDAY", "1");
    lib.defineCMacro("HAVE_GMTIME_R", "1");
    lib.defineCMacro("HAVE_INET_NTOA", "1");
    lib.defineCMacro("HAVE_INTTYPES_H", "1");
    lib.defineCMacro("HAVE_LIMITS_H", "1");
    lib.defineCMacro("HAVE_MEMSET", "1");
    lib.defineCMacro("HAVE_NETDB_H", "1");
    lib.defineCMacro("HAVE_NETINET_IN_H", "1");
    lib.defineCMacro("HAVE_PTHREAD", "1");
    lib.defineCMacro("HAVE_PTHREAD_PRIO_INHERIT", "1");
    lib.defineCMacro("HAVE_SOCKET", "1");
    lib.defineCMacro("HAVE_STDDEF_H", "1");
    lib.defineCMacro("HAVE_STDINT_H", "1");
    lib.defineCMacro("HAVE_STDIO_H", "1");
    lib.defineCMacro("HAVE_STDLIB_H", "1");
    lib.defineCMacro("HAVE_STRFTIME", "1");
    lib.defineCMacro("HAVE_STRING_H", "1");
    lib.defineCMacro("HAVE_STRINGS_H", "1");
    lib.defineCMacro("HAVE_SYS_IOCTL_H", "1");
    lib.defineCMacro("HAVE_SYS_SOCKET_H", "1");
    lib.defineCMacro("HAVE_SYS_STAT_H", "1");
    lib.defineCMacro("HAVE_SYS_TIME_H", "1");
    lib.defineCMacro("HAVE_SYS_TYPES_H", "1");
    lib.defineCMacro("HAVE_SYS_UN_H", "1");
    lib.defineCMacro("HAVE_TIME_H", "1");
    lib.defineCMacro("HAVE___UINT128_T", "1");
    lib.defineCMacro("HAVE_UINTPTR_T", "1");
    lib.defineCMacro("HAVE_UNISTD_H", "1");
    lib.defineCMacro("HAVE_VISIBILITY", "1");
    lib.defineCMacro("SIZEOF_LONG", "8");
    lib.defineCMacro("SIZEOF_LONG_LONG", "8");
    lib.defineCMacro("SIZEOF_TIME_T", "8");

    lib.defineCMacro("BUILDING_WOLFSSL", "");
    lib.defineCMacro("ECC_SHAMIR", "");
    lib.defineCMacro("ECC_TIMING_RESISTANT", "");
    lib.defineCMacro("ERROR_QUEUE_PER_THREAD", "");
    lib.defineCMacro("GCM_TABLE_4BIT", "");
    lib.defineCMacro("HAVE_AESGCM", "");
    lib.defineCMacro("HAVE_CHACHA", "");
    lib.defineCMacro("HAVE_DH_DEFAULT_PARAMS", "");
    lib.defineCMacro("HAVE_ECC", "");
    lib.defineCMacro("HAVE_ENCRYPT_THEN_MAC", "");
    lib.defineCMacro("HAVE_EXTENDED_MASTER", "");
    lib.defineCMacro("HAVE_FFDHE_2048", "");
    lib.defineCMacro("HAVE_HASHDRBG", "");
    lib.defineCMacro("HAVE_HKDF", "");
    lib.defineCMacro("HAVE_POLY1305", "");
    lib.defineCMacro("HAVE_SECURE_RENEGOTIATION", "");
    lib.defineCMacro("HAVE_SERVER_RENEGOTIATION_INFO", "");
    lib.defineCMacro("HAVE_SNI", "");
    lib.defineCMacro("HAVE_SUPPORTED_CURVES", "");
    lib.defineCMacro("HAVE_THREAD_LS", "");
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", "");
    lib.defineCMacro("HAVE_WC_INTROSPECTION", "");
    lib.defineCMacro("NO_DES3", "");
    lib.defineCMacro("NO_DO178", "");
    lib.defineCMacro("NO_DSA", "");
    lib.defineCMacro("NO_INLINE", "");
    lib.defineCMacro("NO_MD4", "");
    lib.defineCMacro("NO_PSK", "");
    lib.defineCMacro("NO_RC4", "");
    lib.defineCMacro("TFM_ECC256", "");
    lib.defineCMacro("TFM_TIMING_RESISTANT", "");
    lib.defineCMacro("WC_NO_ASYNC_THREADING", "");
    lib.defineCMacro("WC_RSA_BLINDING", "");
    lib.defineCMacro("WC_RSA_PSS", "");
    lib.defineCMacro("WOLFSSL_ASN_PRINT", "");
    lib.defineCMacro("WOLFSSL_ASN_TEMPLATE", "");
    lib.defineCMacro("WOLFSSL_BASE64_ENCODE", "");
    lib.defineCMacro("WOLFSSL_HAVE_ATOMIC_H", "");
    lib.defineCMacro("WOLFSSL_NO_SHAKE128", "");
    lib.defineCMacro("WOLFSSL_NO_SHAKE256", "");
    lib.defineCMacro("WOLFSSL_PSS_LONG_SALT", "");
    lib.defineCMacro("WOLFSSL_SHA224", "");
    lib.defineCMacro("WOLFSSL_SHA3", "");
    lib.defineCMacro("WOLFSSL_SHA384", "");
    lib.defineCMacro("WOLFSSL_SHA512", "");
    lib.defineCMacro("WOLFSSL_SP_MATH_ALL", "");
    lib.defineCMacro("WOLFSSL_SYS_CA_CERTS", "");
    lib.defineCMacro("WOLFSSL_TLS13", "");
    lib.defineCMacro("WOLFSSL_USE_ALIGN", "");

    switch (target.getCpuArch()) {
        .x86_64 => {
            lib.defineCMacro("WOLFSSL_SP_X86_64", "");
            lib.defineCMacro("WOLFSSL_X86_64_BUILD", "");
        },
        else => |arch| {
            std.debug.print("Architecture: {any}", .{arch});
            return CompileError.ArchitectureNotSupported;
        },
    }

    if (debug) {
        lib.defineCMacro("DEBUG_WOLFSSL", "");
        lib.defineCMacro("DEBUG", "1");
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
    "-std=c89", "-Wno-int-conversion",
};

const wolfcrypt_flags = [_][]const u8{
    "-std=c89", "-Wno-int-conversion",
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
