const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const crypto = std.crypto;
const Certificate = crypto.Certificate;
const Io = std.Io;

const Transcript = @import("transcript.zig").Transcript;
const PrivateKey = @import("PrivateKey.zig");
const record = @import("record.zig");
const rsa = @import("rsa/rsa.zig");
const proto = @import("protocol.zig");

const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const MLKem768 = crypto.kem.ml_kem.MLKem768;

/// Zappa 1b.23 Bug 1 chip — conservative upper bound on signature size
/// across supported schemes. ECDSA DER: ~104 bytes (P-384). RSA-PSS:
/// up to 512 bytes (4096-bit modulus). Caller-provided sig_buf for
/// `CertKeyPair.signSelfTest` must be at least this large.
pub const MAX_SIGNATURE_LEN: usize = 512;

pub const supported_signature_algorithms = &[_]proto.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .ed25519,
    .rsa_pkcs1_sha1,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
};

pub const CertKeyPair = struct {
    /// A chain of one or more certificates, leaf first.
    ///
    /// Each X.509 certificate contains the public key of a key pair, extra
    /// information (the name of the holder, the name of an issuer of the
    /// certificate, validity time spans) and a signature generated using the
    /// private key of the issuer of the certificate.
    ///
    /// All certificates from the bundle are sent to the other side when creating
    /// Certificate tls message.
    ///
    /// Leaf certificate and private key are used to create signature for
    /// CertifyVerify tls message.
    bundle: Certificate.Bundle,

    /// Private key corresponding to the public key in leaf certificate from the
    /// bundle.
    key: PrivateKey,

    /// Ecdsa key pair derived from key. Computed on init and cached because it
    /// is costly operation. Important for server which is creating many
    /// signatures with the same key to not repeat that operation.
    ecdsa_key_pair: ?EcdsaKeyPair = null,

    pub fn fromFilePath(
        allocator: mem.Allocator,
        io: Io,
        dir: std.Io.Dir,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        const bundle = try cert.fromFilePath(allocator, io, dir, cert_path);
        const key_file = try dir.openFile(io, key_path, .{});
        defer key_file.close(io);
        var rdr = key_file.reader(io, &.{});

        const key = try PrivateKey.fromFile(allocator, &rdr.interface);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn fromFilePathAbsolute(
        allocator: mem.Allocator,
        io: Io,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        const bundle = try cert.fromFilePathAbsolute(allocator, io, cert_path);
        const key_file = try std.Io.Dir.openFileAbsolute(io, key_path, .{});
        defer key_file.close(io);
        var rdr = key_file.reader(io, &.{});

        const key = try PrivateKey.fromFile(allocator, &rdr.interface);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn fromSlice(
        allocator: mem.Allocator,
        io: Io,
        cert_slice: []const u8,
        key_slice: []const u8,
    ) !CertKeyPair {
        const key = try PrivateKey.parsePem(key_slice);
        const bundle = try cert.fromSlice(allocator, io, cert_slice);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn deinit(c: *CertKeyPair, allocator: mem.Allocator) void {
        c.bundle.deinit(allocator);
    }

    /// Zappa 1b.23 Bug 1 chip — sign `message` using the parsed
    /// private key. Reuses the same primitives as
    /// `CertificateBuilder.makeCertificateVerify` (ECDSA via
    /// std.crypto signer chain; RSA-PSS via signerOaep).
    ///
    /// Writes the encoded signature bytes into `sig_buf` and returns
    /// a slice of the bytes used. `sig_buf` must be at least
    /// `MAX_SIGNATURE_LEN` bytes.
    ///
    /// `rng` is required for RSA-PSS (probabilistic). For ECDSA the
    /// signer is deterministic per std.crypto's API; `rng` is ignored
    /// on the ECDSA path.
    pub fn signSelfTest(
        self: *const CertKeyPair,
        message: []const u8,
        sig_buf: []u8,
        rng: std.Random,
    ) ![]const u8 {
        if (sig_buf.len < MAX_SIGNATURE_LEN) return error.SignatureBufferTooSmall;
        switch (self.key.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const key_pair = switch (comptime_scheme) {
                    .ecdsa_secp256r1_sha256 => self.ecdsa_key_pair.?.ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384 => self.ecdsa_key_pair.?.ecdsa_secp384r1_sha384,
                    else => unreachable,
                };
                var signer = try key_pair.signer(null);
                signer.update(message);
                const signature = try signer.finalize();
                const der_len = Ecdsa.Signature.der_encoded_length_max;
                const sig_der = signature.toDer(sig_buf[0..der_len]);
                return sig_der;
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                const Hash = SchemeHash(comptime_scheme);
                var signer = try self.key.key.rsa.signerOaep(Hash, null);
                signer.update(message);
                const signature = try signer.finalize(sig_buf[0..MAX_SIGNATURE_LEN], rng);
                return signature.bytes;
            },
            else => return error.TlsUnknownSignatureScheme,
        }
    }

    /// Zappa 1b.23 Bug 1 chip — verify `signature` against `message`
    /// using the leaf certificate's public key. Reuses the same
    /// primitives as `CertificateParser.verifySignature`.
    ///
    /// Returns the underlying std.crypto verify error on bad signature.
    pub fn verifySelfTest(
        self: *const CertKeyPair,
        message: []const u8,
        signature: []const u8,
    ) !void {
        // Extract leaf DER from the bundle. The bundle bytes contain
        // concatenated DER-encoded certs; the first element is the leaf.
        const certs = self.bundle.bytes.items;
        const leaf_elem = try Certificate.der.Element.parse(certs, 0);
        const leaf_der = certs[0..leaf_elem.slice.end];

        const parsed = try (Certificate{ .buffer = leaf_der, .index = 0 }).parse();
        const pub_key = parsed.pubKey();
        const pub_key_algo = parsed.pub_key_algo;

        switch (self.key.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                if (pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                const cert_named_curve = pub_key_algo.X9_62_id_ecPublicKey;
                switch (cert_named_curve) {
                    inline .secp384r1, .X9_62_prime256v1 => |comptime_cert_named_curve| {
                        const Ecdsa = CertificateParser.SchemeEcdsaCert(comptime_scheme, comptime_cert_named_curve);
                        const key = try Ecdsa.PublicKey.fromSec1(pub_key);
                        const sig = try Ecdsa.Signature.fromDer(signature);
                        try sig.verify(message, key);
                    },
                    else => return error.TlsUnknownSignatureScheme,
                }
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                if (pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = try rsa.PublicKey.fromDer(pub_key);
                const sig = rsa.Pss(Hash).Signature{ .bytes = signature };
                try sig.verify(message, pk, null);
            },
            else => return error.TlsUnknownSignatureScheme,
        }
    }

    const EcdsaKeyPair = union(enum) {
        ecdsa_secp256r1_sha256: EcdsaP256Sha256.KeyPair,
        ecdsa_secp384r1_sha384: EcdsaP384Sha384.KeyPair,

        fn init(pk: PrivateKey) !?EcdsaKeyPair {
            switch (pk.signature_scheme) {
                inline .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                => |comptime_scheme| {
                    const Ecdsa = SchemeEcdsa(comptime_scheme);
                    const key = pk.key.ecdsa;
                    const key_len = Ecdsa.SecretKey.encoded_length;
                    if (key.len < key_len) return error.InvalidEncoding;
                    const secret_key = try Ecdsa.SecretKey.fromBytes(key[0..key_len].*);
                    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
                    return switch (comptime_scheme) {
                        .ecdsa_secp256r1_sha256 => .{ .ecdsa_secp256r1_sha256 = key_pair },
                        .ecdsa_secp384r1_sha384 => .{ .ecdsa_secp384r1_sha384 = key_pair },
                        else => unreachable,
                    };
                },
                else => return null,
            }
        }
    };
};

pub const cert = struct {
    // A chain of one or more certificates.
    //
    // They are used to verify that certificate chain sent by the other side
    // forms valid trust chain.
    pub const Bundle = crypto.Certificate.Bundle;

    pub fn fromFilePath(allocator: mem.Allocator, io: Io, dir: std.Io.Dir, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePath(allocator, io, Io.Clock.real.now(io), dir, path);
        return bundle;
    }

    pub fn fromFilePathAbsolute(allocator: mem.Allocator, io: Io, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePathAbsolute(allocator, io, Io.Clock.real.now(io), path);
        return bundle;
    }

    pub fn fromSystem(allocator: mem.Allocator, io: Io) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.rescan(allocator, io, Io.Clock.real.now(io));
        return bundle;
    }

    pub fn fromSlice(allocator: mem.Allocator, io: Io, slice: []const u8) !Bundle {
        const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const size = slice.len;
        const ts = Io.Clock.real.now(io);

        var bundle: Bundle = .empty;

        //Contains modified code from std.crypto.Certificate.Bundle.addCertsFromFile
        const decoded_size_upper_bound = size / 4 * 3;
        const needed_capacity = std.math.cast(u32, decoded_size_upper_bound + size) orelse
            return Certificate.Bundle.AddCertsFromFileError.CertificateAuthorityBundleTooBig;
        try bundle.bytes.ensureUnusedCapacity(allocator, needed_capacity);
        const end_reserved: u32 = @intCast(bundle.bytes.items.len + decoded_size_upper_bound);
        const buffer = bundle.bytes.allocatedSlice()[end_reserved..];
        @memcpy(buffer[0..size], slice);
        const encoded_bytes = buffer[0..size];

        const begin_marker = "-----BEGIN CERTIFICATE-----";
        const end_marker = "-----END CERTIFICATE-----";

        var start_index: usize = 0;
        while (mem.indexOfPos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
            const cert_start = begin_marker_start + begin_marker.len;
            const cert_end = mem.indexOfPos(u8, encoded_bytes, cert_start, end_marker) orelse
                return Certificate.Bundle.AddCertsFromFileError.MissingEndCertificateMarker;
            start_index = cert_end + end_marker.len;
            const encoded_cert = mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
            const decoded_start: u32 = @intCast(bundle.bytes.items.len);
            const dest_buf = bundle.bytes.allocatedSlice()[decoded_start..];
            bundle.bytes.items.len += try base64.decode(dest_buf, encoded_cert);
            try bundle.parseCert(allocator, decoded_start, ts.toSeconds());
        }
        return bundle;
    }
};

pub const CertificateBuilder = struct {
    /// Caller-owned cert/key bundle to serialize. Read-only — the
    /// builder only inspects bundle bytes + signature schemes; it never
    /// writes through this pointer. Holding it `*const` lets callers
    /// share a single `CertKeyPair` between concurrent handshakes
    /// without copies or const-stripping.
    cert_key_pair: *const CertKeyPair,
    transcript: *Transcript,
    tls_version: proto.Version = .tls_1_3,
    side: proto.Side = .client,
    rng: std.Random,
    /// Phase OCSP-wire — raw `OCSPResponse` bytes to staple into the LEAF
    /// `CertificateEntry`'s extensions (TLS 1.3 only; RFC 8446 §4.4.2.1).
    /// Null = no staple (empty extensions, bit-identical legacy). Caller-
    /// owned + opaque; never freed or inspected here. The caller
    /// (serverFlight) gates this on `client_requested_ocsp`.
    ocsp_staple: ?[]const u8 = null,

    pub fn makeCertificate(h: CertificateBuilder, w: *record.Writer) !void {
        const certs = h.cert_key_pair.bundle.bytes.items;
        const certs_count = h.cert_key_pair.bundle.map.size;

        // TLS 1.3 has request context in header and extensions for each
        // certificate; TLS 1.2 has neither.
        const is_13 = h.tls_version == .tls_1_3;
        const request_context: []const u8 = if (is_13) &[_]u8{0} else &[_]u8{};
        const empty_ext: []const u8 = if (is_13) &[_]u8{ 0, 0 } else &[_]u8{};

        // Phase OCSP-wire — the LEAF (first) cert carries a status_request
        // CertificateEntry extension when a staple is present (TLS 1.3
        // only). Wire (RFC 8446 §4.4.2.1 + RFC 6066 §8):
        //   extensions<u16 total> {
        //     extension_type = 5 (status_request)   // u16
        //     extension_len                          // u16
        //     CertificateStatus {
        //       status_type = 1 (ocsp)               // u8
        //       OCSPResponse<u24 len> = <staple>     // u24 + N
        //     }
        //   }
        // Guard: a staple too large for a u16 extension length (exts_total
        // = 8 + N must fit u16 → N <= 65527) degrades to "no staple".
        var leaf_ext_buf: [9]u8 = undefined;
        const leaf_ext_header: ?[]const u8 = if (is_13 and h.ocsp_staple != null and h.ocsp_staple.?.len <= 65527) blk: {
            const staple = h.ocsp_staple.?;
            const ext_body_len: usize = 1 + 3 + staple.len; // status_type + u24 + body
            const exts_total: usize = 2 + 2 + ext_body_len; // ext_type + ext_len + body
            mem.writeInt(u16, leaf_ext_buf[0..2], @intCast(exts_total), .big);
            mem.writeInt(u16, leaf_ext_buf[2..4], 5, .big); // status_request
            mem.writeInt(u16, leaf_ext_buf[4..6], @intCast(ext_body_len), .big);
            leaf_ext_buf[6] = 1; // status_type = ocsp
            leaf_ext_buf[7] = @intCast((staple.len >> 16) & 0xff); // u24 high
            leaf_ext_buf[8] = @intCast((staple.len >> 8) & 0xff); // u24 mid
            // low u24 byte + staple body are emitted as slices in the loop.
            break :blk leaf_ext_buf[0..9];
        } else null;

        const leaf_ext_total_len: usize = if (leaf_ext_header) |_|
            9 + 1 + h.ocsp_staple.?.len // header(9) + low-len-byte(1) + staple
        else
            empty_ext.len;

        // certs_len: each cert contributes 3 (length prefix) + its extensions.
        // The leaf may have larger extensions than the rest.
        const non_leaf_ext_total: usize = if (is_13) empty_ext.len else 0;
        const certs_len = certs.len + 3 * certs_count + leaf_ext_total_len +
            non_leaf_ext_total * (certs_count - 1);

        try w.handshakeRecordHeader(.certificate, certs_len + request_context.len + 3);
        try w.slice(request_context);
        try w.int(u24, certs_len);

        var index: u32 = 0;
        var cert_i: usize = 0;
        while (index < certs.len) : (cert_i += 1) {
            const e = try Certificate.der.Element.parse(certs, index);
            const crt = certs[index..e.slice.end];
            try w.int(u24, crt.len);
            try w.slice(crt);
            if (cert_i == 0 and leaf_ext_header != null) {
                try w.slice(leaf_ext_header.?);
                const staple = h.ocsp_staple.?;
                try w.slice(&[_]u8{@intCast(staple.len & 0xff)}); // u24 low
                try w.slice(staple);
            } else {
                try w.slice(empty_ext);
            }
            index = e.slice.end;
        }
    }

    pub fn makeCertificateVerify(h: CertificateBuilder, w: *record.Writer) !void {
        // Creates signature for client certificate signature message.
        // Returns signature bytes and signature scheme.
        const signature, const signature_scheme = switch (h.cert_key_pair.key.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| brk: {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const key_pair = switch (comptime_scheme) {
                    .ecdsa_secp256r1_sha256 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp384r1_sha384,
                    else => unreachable,
                };
                var signer = try key_pair.signer(null);
                h.setSignatureVerifyBytes(&signer);
                const signature = try signer.finalize();
                var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                break :brk .{ signature.toDer(&buf), comptime_scheme };
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| brk: {
                const Hash = SchemeHash(comptime_scheme);
                var signer = try h.cert_key_pair.key.key.rsa.signerOaep(Hash, null);
                h.setSignatureVerifyBytes(&signer);
                var buf: [512]u8 = undefined;
                const signature = try signer.finalize(&buf, h.rng);
                break :brk .{ signature.bytes, comptime_scheme };
            },
            else => return error.TlsUnknownSignatureScheme,
        };

        try w.handshakeRecordHeader(.certificate_verify, signature.len + 4);
        try w.enumValue(signature_scheme);
        try w.int(u16, signature.len);
        try w.slice(signature);
    }

    fn setSignatureVerifyBytes(h: CertificateBuilder, signer: anytype) void {
        if (h.tls_version == .tls_1_2) {
            // tls 1.2 signature uses current transcript hash value.
            // ref: https://datatracker.ietf.org/doc/html/rfc5246.html#section-7.4.8
            const Hash = @TypeOf(signer.h);
            signer.h = h.transcript.hash(Hash);
        } else {
            // tls 1.3 signature is computed over concatenation of 64 spaces,
            // context, separator and content.
            // ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
            if (h.side == .server) {
                signer.update(h.transcript.serverCertificateVerify());
            } else {
                signer.update(h.transcript.clientCertificateVerify());
            }
        }
    }
};

fn SchemeEcdsa(comptime scheme: proto.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
        else => unreachable,
    };
}

pub const CertificateParser = struct {
    pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,
    pub_key_buf: [1038]u8 = undefined,
    pub_key: []const u8 = undefined,

    signature_scheme: proto.SignatureScheme = @enumFromInt(0),
    signature_buf: [1024]u8 = undefined,
    signature: []const u8 = undefined,

    root_ca: Certificate.Bundle,
    host: []const u8,
    skip_verify: bool = false,
    now_sec: i64,

    /// Slice of the first (leaf) certificate observed during
    /// `parseCertificate`. Points into the caller-provided record buffer,
    /// so it is VALID ONLY UNTIL `parseCertificate` returns. Callers that
    /// wish to retain the bytes MUST copy into long-lived storage before
    /// the borrowed buffer's lifetime ends.
    leaf_der: ?[]const u8 = null,

    /// Phase 1b.19 — caller-provided backing storage for per-cert DER
    /// slices observed during `parseCertificate`. When non-null, the
    /// parser fills entries `[0..cert_count]` with slices pointing into
    /// the caller-provided record buffer; same lifetime contract as
    /// `leaf_der` (VALID ONLY UNTIL `parseCertificate` returns). Callers
    /// retaining the bytes MUST copy into long-lived storage before
    /// that buffer goes out of scope.
    ///
    /// Pass a slice into a stack-allocated `[max_chain_depth]?[]const u8`
    /// array sized to the configured cap. Storage is filled at indices
    /// `[0..cert_count]`; entries past `cert_count` stay at their
    /// pre-call value (callers should initialize the array to `null`).
    ///
    /// Optional: null = parse leaf only (back-compat with pre-1b.19
    /// callers; `leaf_der` still gets populated as before).
    chain_der_storage: ?[]?[]const u8 = null,

    /// Defensive cap on the number of certs we'll walk in the peer's
    /// Certificate message. Defaults to 255 (u8 max, effectively
    /// unbounded). Callers configuring tighter caps trade compatibility
    /// with deeply-nested chains for fail-early protection.
    max_chain_depth: u8 = 255,

    /// Count of certificates parsed so far in `parseCertificate`. Used
    /// to enforce `max_chain_depth`.
    cert_count: u8 = 0,

    pub fn parseCertificate(h: *CertificateParser, d: *record.Decoder, tls_version: proto.Version) !void {
        if (tls_version == .tls_1_3) {
            const request_context = try d.decode(u8);
            if (request_context != 0) return error.TlsIllegalParameter;
        }

        var trust_chain_established = false;
        var last_cert: ?Certificate.Parsed = null;
        const certs_len = try d.decode(u24);
        const start_idx = d.idx;
        while (d.idx - start_idx < certs_len) {
            // Chain-depth cap. Fail early during the DER walk if the
            // peer's chain exceeds the configured limit.
            if (h.cert_count == h.max_chain_depth) return error.PeerCertChainTooDeep;
            h.cert_count += 1;

            const crt_len = try d.decode(u24);
            const crt = try d.slice(crt_len);
            if (tls_version == .tls_1_3) {
                // certificate extensions present in tls 1.3
                try d.skip(try d.decode(u16));
            }

            // Record the leaf DER on the first cert. The slice points
            // into the caller-owned record buffer; the caller must copy
            // into long-lived memory before that buffer goes out of
            // scope if they want to retain the bytes.
            if (h.leaf_der == null) h.leaf_der = crt;

            // Phase 1b.19 — also record into caller-provided chain
            // storage when configured. `cert_count` was just
            // incremented to N for the Nth cert (1-based) above; store
            // at index N-1. Same lifetime contract as `leaf_der`.
            //
            // Storage is sized to `max_chain_depth` by the caller; the
            // chain-depth cap check at the top of this loop ensures we
            // never index past that bound.
            if (h.chain_der_storage) |storage| {
                const idx: usize = @intCast(h.cert_count - 1);
                if (idx < storage.len) storage[idx] = crt;
            }

            if (trust_chain_established)
                continue;

            const subject = try (Certificate{ .buffer = crt, .index = 0 }).parse();
            if (last_cert) |pc| {
                if (pc.verify(subject, h.now_sec)) {
                    last_cert = subject;
                } else |err| switch (err) {
                    error.CertificateIssuerMismatch => {
                        // skip certificate which is not part of the chain
                        continue;
                    },
                    else => return err,
                }
            } else { // first certificate
                if (!h.skip_verify and h.host.len > 0) {
                    try subject.verifyHostName(h.host);
                }
                h.pub_key = try dupe(&h.pub_key_buf, subject.pubKey());
                h.pub_key_algo = subject.pub_key_algo;
                last_cert = subject;
            }
            if (!h.skip_verify) {
                if (h.root_ca.verify(last_cert.?, h.now_sec)) |_| {
                    trust_chain_established = true;
                } else |err| switch (err) {
                    error.CertificateIssuerNotFound => {},
                    else => return err,
                }
            }
        }
        if (!h.skip_verify and !trust_chain_established) {
            return error.CertificateIssuerNotFound;
        }
    }

    pub fn parseCertificateVerify(h: *CertificateParser, d: *record.Decoder) !void {
        h.signature_scheme = try d.decode(proto.SignatureScheme);
        h.signature = try dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
    }

    pub fn verifySignature(h: *CertificateParser, verify_bytes: []const u8) !void {
        switch (h.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                if (h.pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                const cert_named_curve = h.pub_key_algo.X9_62_id_ecPublicKey;
                switch (cert_named_curve) {
                    inline .secp384r1, .X9_62_prime256v1 => |comptime_cert_named_curve| {
                        const Ecdsa = SchemeEcdsaCert(comptime_scheme, comptime_cert_named_curve);
                        const key = try Ecdsa.PublicKey.fromSec1(h.pub_key);
                        const sig = try Ecdsa.Signature.fromDer(h.signature);
                        try sig.verify(verify_bytes, key);
                    },
                    else => return error.TlsUnknownSignatureScheme,
                }
            },
            .ed25519 => {
                if (h.pub_key_algo != .curveEd25519) return error.TlsBadSignatureScheme;
                const Eddsa = crypto.sign.Ed25519;
                if (h.signature.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                const sig = Eddsa.Signature.fromBytes(h.signature[0..Eddsa.Signature.encoded_length].*);
                if (h.pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                const key = try Eddsa.PublicKey.fromBytes(h.pub_key[0..Eddsa.PublicKey.encoded_length].*);
                try sig.verify(verify_bytes, key);
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.Pss(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk, null);
            },
            inline .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.PKCS1v1_5(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk);
            },
            else => return error.TlsUnknownSignatureScheme,
        }
    }

    pub fn SchemeEcdsaCert(comptime scheme: proto.SignatureScheme, comptime cert_named_curve: Certificate.NamedCurve) type {
        const Sha256 = crypto.hash.sha2.Sha256;
        const Sha384 = crypto.hash.sha2.Sha384;
        const Ecdsa = crypto.sign.ecdsa.Ecdsa;

        return switch (scheme) {
            .ecdsa_secp256r1_sha256 => Ecdsa(cert_named_curve.Curve(), Sha256),
            .ecdsa_secp384r1_sha384 => Ecdsa(cert_named_curve.Curve(), Sha384),
            else => @compileError("bad scheme"),
        };
    }
};

fn SchemeHash(comptime scheme: proto.SignatureScheme) type {
    const Sha256 = crypto.hash.sha2.Sha256;
    const Sha384 = crypto.hash.sha2.Sha384;
    const Sha512 = crypto.hash.sha2.Sha512;

    return switch (scheme) {
        .rsa_pkcs1_sha1 => crypto.hash.Sha1,
        .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => Sha256,
        .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => Sha384,
        .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => Sha512,
        else => @compileError("bad scheme"),
    };
}

pub fn dupe(buf: []u8, data: []const u8) ![]u8 {
    if (buf.len < data.len) {
        return error.BufferUndersize;
    }
    @memcpy(buf[0..data.len], data);
    return buf[0..data.len];
}

pub fn dupeMin(buf: []u8, data: []const u8) []u8 {
    const n = @min(data.len, buf.len);
    @memcpy(buf[0..n], data[0..n]);
    return buf[0..n];
}

pub const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
    ml_kem768: MLKem768.KeyPair = undefined,

    secp256r1_pk_buf: [EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //65 bytes
    secp384r1_pk_buf: [EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //97
    ml_kem768_pk_buf: [MLKem768.PublicKey.encoded_length + X25519.public_length]u8 = undefined, // 1216
    shared_key_buf: [64]u8 = undefined,

    pub const seed_len = 32 + 32 + 48 + 64 + 64;

    pub fn init(seed: [seed_len]u8, named_groups: []const proto.NamedGroup) !DhKeyPair {
        var kp: DhKeyPair = .{};
        for (named_groups) |ng|
            switch (ng) {
                .x25519 => kp.x25519_kp = try X25519.KeyPair.generateDeterministic(seed[0..][0..X25519.seed_length].*),
                .secp256r1 => kp.secp256r1_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed[32..][0..EcdsaP256Sha256.KeyPair.seed_length].*),
                .secp384r1 => kp.secp384r1_kp = try EcdsaP384Sha384.KeyPair.generateDeterministic(seed[32 + 32 ..][0..EcdsaP384Sha384.KeyPair.seed_length].*),
                .x25519_ml_kem768 => kp.ml_kem768 = try MLKem768.KeyPair.generateDeterministic(seed[32 + 32 + 48 + 64 ..][0..MLKem768.seed_length].*),
                else => return error.TlsIllegalParameter,
            };
        return kp;
    }

    // x25519: 32,  secp256r1: 32, secp384r1: 48, x25519_ml_kem768: 64
    pub fn sharedKey(self: *DhKeyPair, named_group: proto.NamedGroup, server_pub_key: []const u8) ![]const u8 {
        return switch (named_group) {
            .x25519 => {
                if (server_pub_key.len != X25519.public_length)
                    return error.TlsIllegalParameter;
                self.shared_key_buf[0..32].* = try X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..X25519.public_length].*,
                );
                return self.shared_key_buf[0..32];
            },
            .secp256r1 => {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp256r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..32].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..32];
            },
            .secp384r1 => {
                const pk = try EcdsaP384Sha384.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp384r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..48].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..48];
            },
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = self.ml_kem768.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(self.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                self.shared_key_buf = (hsk ++ xsk);
                return &self.shared_key_buf;
            },
            else => return error.TlsIllegalParameter,
        };
    }

    // Returns 32, 65, 97 or 1216 bytes ml_kem
    pub fn publicKey(self: *DhKeyPair, named_group: proto.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => {
                self.secp256r1_pk_buf = self.secp256r1_kp.public_key.toUncompressedSec1();
                return &self.secp256r1_pk_buf;
            },
            .secp384r1 => {
                self.secp384r1_pk_buf = self.secp384r1_kp.public_key.toUncompressedSec1();
                return &self.secp384r1_pk_buf;
            },
            .x25519_ml_kem768 => {
                self.ml_kem768_pk_buf = self.ml_kem768.public_key.toBytes() ++ self.x25519_kp.public_key;
                return &self.ml_kem768_pk_buf;
            },
            else => return error.TlsIllegalParameter,
        };
    }
};

const testing = std.testing;
const testu = @import("testu.zig");

test "DhKeyPair.x25519" {
    var seed: [DhKeyPair.seed_len]u8 = undefined;
    testu.fill(&seed);
    const server_pub_key = &testu.hexToBytes("3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = &testu.hexToBytes(
        \\ F1 67 FB 4A 49 B2 91 77  08 29 45 A1 F7 08 5A 21
        \\ AF FE 9E 78 C2 03 9B 81  92 40 72 73 74 7A 46 1E
    );
    var kp = try DhKeyPair.init(seed, &.{.x25519});
    try testing.expectEqualSlices(u8, expected, try kp.sharedKey(.x25519, server_pub_key));
}

test "CertificateParser: chain_der_storage captures every cert slice in order" {
    // Drives parseCertificate directly with a hand-built record.Decoder
    // containing 3 concatenated copies of the same self-signed leaf DER.
    // skip_verify = true bypasses the chain-walk verify step (each cert
    // would otherwise fail with IssuerMismatch against itself); the
    // chain_der_storage capture happens BEFORE the verify gate so this
    // test pins the storage shape without needing a real multi-cert
    // chain fixture.
    //
    // The companion 3-cert end-to-end test (real handshake with real
    // chain) lives in handshake_server.zig — this one isolates the
    // CertificateParser surface.
    const alloc = testing.allocator;
    const cert_pem = @embedFile("testdata/mtls_test_cert.pem");

    // Extract the leaf DER from the PEM fixture via cert.fromSlice.
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bundle = try cert.fromSlice(alloc, io, cert_pem);
    defer bundle.deinit(alloc);

    var it = bundle.map.iterator();
    const entry = it.next() orelse return error.NoCertInFixture;
    const offset = entry.value_ptr.*;
    const outer = try Certificate.der.Element.parse(bundle.bytes.items, offset);
    const leaf_der = bundle.bytes.items[offset..outer.slice.end];

    // Hand-build a record.Decoder buffer for the post-record-header
    // bytes parseCertificate consumes: u8 request_context (0 for tls
    // 1.3 server-flight Certificate message), u24 certs_len, then for
    // each cert: u24 crt_len, crt bytes, u16 extensions_len (0 for tls
    // 1.3).
    const n_certs = 3;
    const per_cert_overhead = 3 + 2; // u24 crt_len + u16 extensions_len
    const certs_len: u24 = @intCast((leaf_der.len + per_cert_overhead) * n_certs);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    // u8 request_context (tls 1.3): must be 0 in server flight.
    try buf.append(alloc, 0);
    // certs_len header
    try buf.append(alloc, @intCast((certs_len >> 16) & 0xff));
    try buf.append(alloc, @intCast((certs_len >> 8) & 0xff));
    try buf.append(alloc, @intCast(certs_len & 0xff));
    var i: usize = 0;
    while (i < n_certs) : (i += 1) {
        const cl: u24 = @intCast(leaf_der.len);
        try buf.append(alloc, @intCast((cl >> 16) & 0xff));
        try buf.append(alloc, @intCast((cl >> 8) & 0xff));
        try buf.append(alloc, @intCast(cl & 0xff));
        try buf.appendSlice(alloc, leaf_der);
        try buf.append(alloc, 0); // extensions_len high byte
        try buf.append(alloc, 0); // extensions_len low byte
    }

    var dec: record.Decoder = .init(.handshake, buf.items);
    var root_ca = try cert.fromSlice(alloc, io, cert_pem);
    defer root_ca.deinit(alloc);

    var storage: [4]?[]const u8 = .{ null, null, null, null };
    var parser: CertificateParser = .{
        .root_ca = root_ca,
        .host = "",
        .skip_verify = true,
        .now_sec = std.Io.Clock.real.now(io).toSeconds(),
        .chain_der_storage = storage[0..],
    };

    try parser.parseCertificate(&dec, .tls_1_3);

    try testing.expectEqual(@as(u8, 3), parser.cert_count);
    try testing.expect(parser.leaf_der != null);
    try testing.expectEqualSlices(u8, leaf_der, parser.leaf_der.?);

    // chain_der_storage[0..2] must each hold the same DER (leaf-first
    // ordering is universal; this is the load-bearing assertion).
    try testing.expect(storage[0] != null);
    try testing.expect(storage[1] != null);
    try testing.expect(storage[2] != null);
    try testing.expectEqual(@as(?[]const u8, null), storage[3]); // unused slot
    try testing.expectEqualSlices(u8, leaf_der, storage[0].?);
    try testing.expectEqualSlices(u8, leaf_der, storage[1].?);
    try testing.expectEqualSlices(u8, leaf_der, storage[2].?);
}

test "CertificateParser: chain_der_storage null preserves back-compat (no capture)" {
    // When chain_der_storage is null, parseCertificate behaves exactly
    // as before 1b.19 — leaf_der captured, chain not. Pins the
    // back-compat contract for pre-1b.19 callers.
    const alloc = testing.allocator;
    const cert_pem = @embedFile("testdata/mtls_test_cert.pem");

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bundle = try cert.fromSlice(alloc, io, cert_pem);
    defer bundle.deinit(alloc);

    var it = bundle.map.iterator();
    const entry = it.next() orelse return error.NoCertInFixture;
    const offset = entry.value_ptr.*;
    const outer = try Certificate.der.Element.parse(bundle.bytes.items, offset);
    const leaf_der = bundle.bytes.items[offset..outer.slice.end];

    const certs_len: u24 = @intCast(leaf_der.len + 5);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    // u8 request_context (tls 1.3): must be 0 in server flight.
    try buf.append(alloc, 0);
    try buf.append(alloc, @intCast((certs_len >> 16) & 0xff));
    try buf.append(alloc, @intCast((certs_len >> 8) & 0xff));
    try buf.append(alloc, @intCast(certs_len & 0xff));
    const cl: u24 = @intCast(leaf_der.len);
    try buf.append(alloc, @intCast((cl >> 16) & 0xff));
    try buf.append(alloc, @intCast((cl >> 8) & 0xff));
    try buf.append(alloc, @intCast(cl & 0xff));
    try buf.appendSlice(alloc, leaf_der);
    try buf.append(alloc, 0);
    try buf.append(alloc, 0);

    var dec: record.Decoder = .init(.handshake, buf.items);
    var root_ca = try cert.fromSlice(alloc, io, cert_pem);
    defer root_ca.deinit(alloc);

    var parser: CertificateParser = .{
        .root_ca = root_ca,
        .host = "",
        .skip_verify = true,
        .now_sec = std.Io.Clock.real.now(io).toSeconds(),
        // chain_der_storage left null
    };

    try parser.parseCertificate(&dec, .tls_1_3);
    try testing.expectEqual(@as(u8, 1), parser.cert_count);
    try testing.expect(parser.leaf_der != null);
    // No storage was provided → no per-slice capture happened.
    try testing.expectEqual(@as(?[]?[]const u8, null), parser.chain_der_storage);
}

test "1b.23 Bug 1 chip — CertKeyPair.signSelfTest + verifySelfTest round-trip (ECDSA P-256)" {
    const alloc = testing.allocator;
    const cert_pem = @embedFile("testdata/mtls_test_cert.pem");
    const key_pem = @embedFile("testdata/mtls_test_key.pem");

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try CertKeyPair.fromSlice(alloc, io, cert_pem, key_pem);
    defer pair.deinit(alloc);

    const message = "test-vector";
    var sig_buf: [MAX_SIGNATURE_LEN]u8 = undefined;
    const sig = try pair.signSelfTest(message, &sig_buf, testu.random(0));
    try pair.verifySelfTest(message, sig);
}

test "1b.23 Bug 1 chip — verifySelfTest rejects wrong message" {
    const alloc = testing.allocator;
    const cert_pem = @embedFile("testdata/mtls_test_cert.pem");
    const key_pem = @embedFile("testdata/mtls_test_key.pem");

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try CertKeyPair.fromSlice(alloc, io, cert_pem, key_pem);
    defer pair.deinit(alloc);

    var sig_buf: [MAX_SIGNATURE_LEN]u8 = undefined;
    const sig = try pair.signSelfTest("message-a", &sig_buf, testu.random(0));
    // ECDSA verify over a wrong message produces an invalid-signature error.
    // The exact error name may be SignatureVerificationFailed or similar.
    const result = pair.verifySelfTest("message-b", sig);
    try testing.expectError(error.SignatureVerificationFailed, result);
}

test "OCSP-wire — makeCertificate stapled leaf CertificateEntry round-trips" {
    const alloc = testing.allocator;
    const cert_pem = @embedFile("testdata/mtls_test_cert.pem");
    const key_pem = @embedFile("testdata/mtls_test_key.pem");

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ckp = try CertKeyPair.fromSlice(alloc, io, cert_pem, key_pem);
    defer ckp.deinit(alloc);

    var transcript: Transcript = .{};
    const staple = "OCSPRESPONSEBYTES"; // 17 bytes
    var buf: [4096]u8 = undefined;
    var w: record.Writer = .init(&buf);

    const cb = CertificateBuilder{
        .cert_key_pair = &ckp,
        .transcript = &transcript,
        .tls_version = .tls_1_3,
        .side = .server,
        .rng = testu.random(0),
        .ocsp_staple = staple,
    };
    try cb.makeCertificate(&w);
    const out = w.buffered();

    // Handshake type byte must be certificate (0x0b = 11).
    try testing.expectEqual(@as(u8, 11), out[0]);

    // The raw staple bytes must appear verbatim somewhere in the output.
    const idx = std.mem.indexOf(u8, out, staple) orelse return error.StapleNotFound;

    // Wire layout immediately before the staple (offsets relative to idx):
    //   idx-10: exts_total high (0x00)
    //   idx-9:  exts_total low  (0x19 = 25)
    //   idx-8:  ext_type high   (0x00)
    //   idx-7:  ext_type low    (0x05 = status_request)
    //   idx-6:  ext_body_len high (0x00)
    //   idx-5:  ext_body_len low  (0x15 = 21 = 1+3+17)
    //   idx-4:  status_type     (0x01 = ocsp)
    //   idx-3:  u24 high        (0x00)
    //   idx-2:  u24 mid         (0x00)
    //   idx-1:  u24 low         (0x11 = 17)
    try testing.expectEqual(@as(u8, 0x00), out[idx - 8]); // ext_type high
    try testing.expectEqual(@as(u8, 0x05), out[idx - 7]); // status_request type
    try testing.expectEqual(@as(u8, 0x01), out[idx - 4]); // status_type = ocsp
    try testing.expectEqual(@as(u8, 0x00), out[idx - 3]); // u24 high
    try testing.expectEqual(@as(u8, 0x00), out[idx - 2]); // u24 mid
    try testing.expectEqual(@as(u8, 0x11), out[idx - 1]); // u24 low = 17
}

test "OCSP-wire — makeCertificate without staple emits empty leaf extensions" {
    const alloc = testing.allocator;
    const cert_pem = @embedFile("testdata/mtls_test_cert.pem");
    const key_pem = @embedFile("testdata/mtls_test_key.pem");

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ckp = try CertKeyPair.fromSlice(alloc, io, cert_pem, key_pem);
    defer ckp.deinit(alloc);

    var transcript: Transcript = .{};
    var buf: [4096]u8 = undefined;
    var w: record.Writer = .init(&buf);

    const cb = CertificateBuilder{
        .cert_key_pair = &ckp,
        .transcript = &transcript,
        .tls_version = .tls_1_3,
        .side = .server,
        .rng = testu.random(0),
        .ocsp_staple = null,
    };
    try cb.makeCertificate(&w);
    const out = w.buffered();

    // Wire layout: header(4) + reqctx(1) + certs_len(3) + leaf_len(3) + leaf_DER
    // out[8..11] = u24 leaf_len
    const leaf_len = (@as(usize, out[8]) << 16) | (@as(usize, out[9]) << 8) | out[10];
    const ext_off = 11 + leaf_len;
    // Empty extensions = two zero bytes.
    try testing.expectEqual(@as(u8, 0), out[ext_off]);
    try testing.expectEqual(@as(u8, 0), out[ext_off + 1]);
}
