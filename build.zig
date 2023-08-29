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

    // on by default
    lib.defineCMacro("HAVE_SUPPORTED_CURVES", null);
    lib.defineCMacro("HAVE_EXTENDED_MASTER", null);
    lib.defineCMacro("HAVE_ENCRYPT_THEN_MAC", null);
    lib.defineCMacro("HAVE_ONE_TIME_AUTH", null);

    // lib.defineCMacro("WOLFSSL_ASN_PRINT", null);
    // lib.defineCMacro("WOLFSSL_POST_HANDSHAKE_AUTH", null);
    // lib.defineCMacro("WOLFSSL_SEND_HRR_COOKIE", null);
    lib.defineCMacro("WOLFSSL_SHA3", null);
    lib.defineCMacro("WOLFSSL_SHA512", null);

    // for custom IO
    lib.defineCMacro("WOLFSSL_USER_IO", null);

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
