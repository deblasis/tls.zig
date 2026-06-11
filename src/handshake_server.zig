// PATCHED FROM upstream ianic/tls.zig (bc2e190 base)
// Phase 1b.13 — leaf cert DER capture (peerCertificate)
// Phase 1b.14 — SNI dispatch (setAuth, awaiting_auth pause, sniHost, rejectNoMatch)
// Phase 1b.19 — chain bytes retention (retain_chain, peerChain)
// Phase 1b.24 — setAuth widened to take ?ClientAuth + ?alpn_protocols overrides

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const Io = std.Io;
const Certificate = std.crypto.Certificate;

const Cipher = @import("cipher.zig").Cipher;
const CipherSuite = @import("cipher.zig").CipherSuite;
const cipher_suites = @import("cipher.zig").cipher_suites;
const max_cleartext_len = @import("cipher.zig").max_cleartext_len;

const Transcript = @import("transcript.zig").Transcript;
const record = @import("record.zig");
const Record = record.Record;
const PrivateKey = @import("PrivateKey.zig");
const proto = @import("protocol.zig");

const common = @import("handshake_common.zig");
const CertificateBuilder = common.CertificateBuilder;
const CertificateParser = common.CertificateParser;
const DhKeyPair = common.DhKeyPair;
const CertKeyPair = common.CertKeyPair;
const cert = common.cert;

const log = std.log.scoped(.tls);

pub const Options = struct {
    rng: std.Random,

    /// Server authentication. If null server will not send Certificate and
    /// CertificateVerify message. Pointer is read-only — the library
    /// never mutates the underlying `CertKeyPair`.
    auth: ?*const CertKeyPair,

    /// If not null server will request client certificate. If auth_type is
    /// .request empty client certificate message will be accepted.
    /// Client certificate will be verified with root_ca certificates.
    client_auth: ?ClientAuth = null,

    /// List of supported tls 1.3 cipher suites
    cipher_suites: []const CipherSuite = cipher_suites.tls13,

    /// ALPN protocol names supported by the server, in preference order.
    /// If empty, no ALPN extension is sent in the response.
    alpn_protocols: []const []const u8 = &.{},

    now: Io.Timestamp,
};

pub const ClientAuth = struct {
    /// Set of root certificate authorities that server use when verifying
    /// client certificates.
    root_ca: cert.Bundle,

    auth_type: Type = .require,

    /// Defensive cap on cert chain depth. The library will fail-early
    /// with `error.PeerCertChainTooDeep` if the client's Certificate
    /// message carries more entries than this cap. Default is 255 (u8
    /// max, effectively unbounded) to preserve back-compat. Callers
    /// concerned about pathological chain depth can tighten this.
    max_chain_depth: u8 = 255,

    /// Phase 1b.19 — when true, the engine duplicates each verified
    /// chain cert's DER bytes into long-lived allocator-owned storage
    /// on the `NonBlock.Server`, surfaced via `peerChain()`. Default
    /// false preserves the pre-1b.19 bench profile (no extra
    /// allocations per handshake).
    ///
    /// Requires `Handshake.allocator` to be non-null (i.e., the server
    /// was constructed via `initWithAllocator` / `initForSniDispatch`).
    /// Otherwise this flag is silently ignored — same as `peer_cert_der`
    /// is silently null on a no-allocator instance.
    retain_chain: bool = false,

    /// Phase 1b.25 — pre-encoded `certificate_authorities` extension
    /// payload (RFC 8446 §4.2.4). When non-null, written verbatim into
    /// the CertificateRequest extensions block under
    /// extension_type = 47 (0x002F). Format: `<u16 authorities_length>
    /// <N × (<u16 dn_len><dn_bytes>)>`.
    ///
    /// Caller (zappa) owns the bytes; library never copies, frees, or
    /// inspects them — opaque from the library's perspective. null =
    /// extension omitted.
    cert_authorities_ext_bytes: ?[]const u8 = null,

    pub const Type = enum {
        /// Client certificate will be requested during the handshake, but does
        /// not require that the client send any certificates.
        request,
        /// Client certificate will be requested during the handshake, and client
        /// has to send valid certificate.
        require,
    };
};

pub const Handshake = struct {
    // public key len: x25519 = 32, secp256r1 = 65, secp384r1 = 97
    const max_pub_key_len = 98;
    const supported_named_groups = &[_]proto.NamedGroup{ .x25519, .secp256r1, .secp384r1 };

    /// Underlying network connection stream reader/writer pair.
    input: *Io.Reader,
    output: *Io.Writer,

    server_random: [32]u8 = undefined,
    client_random: [32]u8 = undefined,
    legacy_session_id_buf: [32]u8 = undefined,
    legacy_session_id: []u8 = &.{},
    cipher_suite: CipherSuite = @enumFromInt(0),
    signature_scheme: proto.SignatureScheme = @enumFromInt(0),
    named_group: proto.NamedGroup = @enumFromInt(0),
    client_pub_key_buf: [max_pub_key_len]u8 = undefined,
    client_pub_key: []u8 = &.{},
    server_pub_key_buf: [max_pub_key_len]u8 = undefined,
    server_pub_key: []u8 = &.{},

    cipher: Cipher = undefined,
    transcript: Transcript = .{},
    /// ALPN protocol selected during handshake.
    alpn_protocol: ?[]const u8 = null,

    /// Optional allocator used to dupe the verified peer leaf cert DER
    /// into long-lived memory in `readClientFlight2`. Null = legacy
    /// behavior (no leaf capture, no allocation). When non-null AND
    /// `opt.client_auth` is configured AND the peer presents a non-empty
    /// cert, the leaf bytes are duped on success; the copy lifetime
    /// equals `NonBlock.Server` lifetime (deinit frees).
    allocator: ?std.mem.Allocator = null,

    /// Allocator-owned copy of the verified peer's leaf certificate
    /// DER. Populated on successful mTLS handshake when
    /// `allocator != null`; freed by `NonBlock.Server.deinit`. Null in
    /// these cases:
    ///   - allocator is null (legacy path),
    ///   - mTLS not configured (`opt.client_auth == null`),
    ///   - client presented an empty Certificate message in `.request` mode,
    ///   - handshake has not reached the certificate flight yet,
    ///   - OOM during dupe (handshake aborts with `error.OutOfMemory`).
    peer_cert_der: ?[]const u8 = null,

    /// Phase 1b.19 — allocator-owned copy of the verified peer's full
    /// chain DER bytes (leaf at index 0, intermediates after — matches
    /// the RFC 8446 §4.4.2 wire order). Populated by `readClientFlight2`
    /// when `allocator != null` AND `opt.client_auth.?.retain_chain ==
    /// true` AND the peer presented a non-empty cert. Null in all other
    /// cases (mirrors `peer_cert_der`'s null contract).
    ///
    /// Each element is its own `allocator.dupe`'d copy; the slice-of-
    /// slices is itself allocator-owned. Freed in
    /// `NonBlock.Server.deinit`.
    peer_chain_der: ?[]const []const u8 = null,

    /// Inline storage for the parsed SNI hostname. 256 bytes is the
    /// round-number safety margin over RFC 5890's 253-octet DNS hostname
    /// cap (SNI per RFC 6066 §3 prohibits the trailing dot, so 253 is
    /// the effective max). Bytes are meaningful only when
    /// `sni_host_len > 0`. Pinned to Handshake lifetime; NOT a slice
    /// into the input buffer (which would dangle across the
    /// `awaiting_auth` pause introduced in a follow-up commit).
    sni_host_buf: [256]u8 = undefined,

    /// Length of the parsed SNI hostname in `sni_host_buf`. Zero means
    /// SNI was absent OR malformed (we treat malformed SNI as absent —
    /// defensive, falls back to default cert). `sniHost()` returns
    /// `sni_host_buf[0..sni_host_len]` when non-zero, null otherwise.
    sni_host_len: u8 = 0,

    /// Cached client `signature_algorithms` list from ClientHello.
    /// Populated during `readClientHello`'s signature_algorithms branch.
    /// After SNI-driven `setAuth()` resolves the auth,
    /// `finalizeAuthAndValidateSigScheme` checks the resolved cert's
    /// signature scheme against this cache (since the original
    /// ClientHello bytes are gone by then). 64 entries is well over
    /// the realistic upper bound (~15 schemes).
    client_signature_schemes_buf: [64]proto.SignatureScheme = undefined,
    client_signature_schemes_len: u8 = 0,

    /// Auth-resolution gate. Set true when:
    ///   (a) legacy construction: Options.auth was non-null at init
    ///       time — `initWithAllocator` populates `opt_auth` and sets
    ///       this true so the new awaiting_auth pause is skipped
    ///       (bit-identical legacy behavior).
    ///   (b) SNI dispatch: caller invokes `setAuth()` (or
    ///       `rejectNoMatch`) after `readClientHello` returns; this
    ///       flag advances the state machine past the pause.
    auth_resolved: bool = false,

    /// Runtime-resolved server auth. The load-bearing pointer that
    /// `serverFlight` reads instead of `opt.auth` directly. Legacy
    /// callers populate this at construction; SNI callers populate via
    /// `setAuth()`. The data behind the pointer is owned by the caller,
    /// not the library, and is treated as immutable throughout the
    /// handshake.
    opt_auth: ?*const CertKeyPair = null,

    /// Set by `rejectNoMatch()`. When true, `serverFlight` raises
    /// `error.TlsUnrecognizedName` before emitting any post-ClientHello
    /// flight bytes. The engine's existing alert-from-error machinery
    /// translates the error into TLS alert `unrecognized_name(112)` per
    /// RFC 6066 §3.
    no_match_abort: bool = false,

    /// Phase 1b.24 — raw bytes of the client's ALPN protocol list
    /// (the wire content AFTER the 2-byte outer list_len field in the
    /// application_layer_protocol_negotiation extension — i.e. the
    /// sequence of <u8 len + proto_bytes> entries). Zero length means the
    /// client sent no ALPN extension OR sent an empty list.
    /// Written during `readClientHello` ONLY when the server has a
    /// non-empty `server_alpn_protocols` list (i.e. `Options.alpn_protocols
    /// .len > 0`), so that `setAuth()` can re-run ALPN selection when an
    /// `alpn_protocols` override is supplied. 512 bytes is well above any
    /// realistic ClientHello ALPN list (typical entries: "h2"=2,
    /// "http/1.1"=9, each prefixed by 1-byte length → rarely > 64 bytes).
    /// Oversized lists (> 512 bytes) are rejected with `error.TlsDecodeError`.
    client_alpn_list_buf: [512]u8 = undefined,
    /// Number of valid bytes in `client_alpn_list_buf`. Zero until
    /// `readClientHello` has consumed the ALPN extension.
    /// Note: this field is also `0` when the client sent no ALPN extension
    /// at all (vs sent an empty list). The two cases are conflated by the
    /// engine — both produce a null `alpn_protocol`. The protocol-level
    /// distinction (RFC 7301 §3.1 calls an empty list malformed) is not
    /// surfaced — pre-existing baseline behavior.
    client_alpn_list_len: u16 = 0,

    /// Phase 1b.24 — set by `setAuth()` when a non-null `alpn_protocols`
    /// override is supplied AND the re-run ALPN selection finds no overlap
    /// between the override list and the client's offer. When true,
    /// `serverFlight` surfaces `error.TlsNoApplicationProtocol` before
    /// emitting any flight bytes — mirroring the existing inline behavior
    /// in `readClientHello`.
    alpn_no_match: bool = false,

    /// Phase OCSP-wire — set true when the ClientHello carried a
    /// `status_request` (5) extension (RFC 6066 §8). Read by
    /// `serverFlight` to decide whether to emit the stapled
    /// `CertificateEntry` extension, and surfaced via
    /// `NonBlock.Server.clientRequestedOcsp()` for the caller's
    /// must-staple gate. Pure superset of the prior `else => skip`
    /// behavior — sets a flag, consumes the same bytes.
    client_requested_ocsp: bool = false,

    /// Phase OCSP-wire — caller-owned raw `OCSPResponse` bytes to staple
    /// into the leaf `CertificateEntry`. Set via `setAuth`'s 4th param.
    /// Null = no staple. The library never copies, frees, or inspects these
    /// bytes (opaque, like `ClientAuth.cert_authorities_ext_bytes`).
    ocsp_staple: ?[]const u8 = null,

    const Self = @This();

    /// Accessor for the parsed SNI hostname. Returns null when
    /// sni_host_len == 0 (absent OR malformed); else returns
    /// `sni_host_buf[0..sni_host_len]`. Lifetime = Handshake lifetime
    /// (inline buffer is pinned).
    pub fn sniHost(self: *const Self) ?[]const u8 {
        if (self.sni_host_len == 0) return null;
        return self.sni_host_buf[0..self.sni_host_len];
    }

    /// Accessor for the verified peer's leaf DER bytes. Returns null
    /// when the handshake has not captured one. Lifetime equals the
    /// owning `NonBlock.Server` (freed by `deinit`).
    pub fn peerCertificate(self: *const Self) ?[]const u8 {
        return self.peer_cert_der;
    }

    /// Accessor for the verified peer's full chain DER bytes (leaf at
    /// index 0). Returns null when no chain was captured (allocator
    /// null, mTLS off, empty cert flight, OR `retain_chain` off).
    /// Lifetime equals the owning `NonBlock.Server` (freed by `deinit`).
    pub fn peerChain(self: *const Self) ?[]const []const u8 {
        return self.peer_chain_der;
    }

    fn writeAlert(h: *Self, cph: ?*Cipher, err: anyerror) !void {
        if (cph) |c| {
            const cleartext = proto.alertFromError(err);
            const ciphertext = try c.encrypt(h.output.unusedCapacitySlice(), .alert, &cleartext);
            h.output.advance(ciphertext.len);
        } else {
            const alert = record.header(.alert, 2) ++ proto.alertFromError(err);
            try h.output.writeAll(&alert);
        }
        try h.output.flush();
    }

    pub fn handshake(h: *Self, opt: Options) !Cipher {
        h.initKeys(opt);

        h.readClientHello(opt.cipher_suites, opt.alpn_protocols) catch |err| {
            try h.writeAlert(null, err);
            return err;
        };
        h.transcript.use(h.cipher_suite.hash());

        h.serverFlight(opt) catch |err| {
            try h.writeAlert(null, err);
            return err;
        };
        try h.output.flush();

        h.clientFlight2(opt) catch |err| {
            // Alert received from client
            if (!mem.startsWith(u8, @errorName(err), "TlsAlert")) {
                try h.writeAlert(&h.cipher, err);
            }
            return err;
        };
        return h.cipher;
    }

    fn initKeys(h: *Self, opt: Options) void {
        opt.rng.bytes(&h.server_random);
        // Derive signature_scheme from the currently-known auth:
        // opt_auth (set by `setAuth()` for SNI dispatch) takes
        // precedence over opt.auth (set at construction for legacy
        // callers). When neither is set yet (SNI awaiting setAuth),
        // leave signature_scheme = 0; the value is finalized in
        // `finalizeAuthAndValidateSigScheme` after setAuth.
        const auth = h.opt_auth orelse opt.auth;
        if (auth) |a| {
            // required signature scheme in client hello
            h.signature_scheme = a.key.signature_scheme;
        }
    }

    /// Validate the resolved auth's signature scheme against the
    /// client's offered `signature_algorithms`, then set
    /// `h.signature_scheme`. Called after `setAuth()` for SNI dispatch;
    /// no-op when h.opt_auth was already resolved at construction
    /// (initKeys already set h.signature_scheme + readClientHello
    /// already validated inline).
    ///
    /// Returns error.TlsHandshakeFailure if the resolved cert's
    /// signature scheme isn't in the client's offered set. The engine
    /// emits handshake_failure(40) before any Certificate bytes hit the
    /// wire — cleaner than letting the client reject post-Certificate
    /// with a confusing decode-error alert.
    fn finalizeAuthAndValidateSigScheme(h: *Self) !void {
        const auth = h.opt_auth orelse return; // no auth: server-without-cert mode
        h.signature_scheme = auth.key.signature_scheme;
        // If the client didn't send signature_algorithms (rare but
        // spec-legal for TLS 1.3 when only PSK is in play), the lib's
        // existing client-flight would have already errored. With a
        // non-empty cache: validate.
        if (h.client_signature_schemes_len == 0) return;
        for (h.client_signature_schemes_buf[0..h.client_signature_schemes_len]) |scheme| {
            if (scheme == h.signature_scheme) return;
        }
        return error.TlsHandshakeFailure;
    }

    fn clientFlight1(h: *Self, opt: Options) !void {
        try h.readClientHello(opt.cipher_suites, opt.alpn_protocols);
        h.transcript.use(h.cipher_suite.hash());
    }

    fn clientFlight2(h: *Self, opt: Options) !void {
        // calculate application cipher before updating transcript in readClientFlight2
        const application_secret = h.transcript.applicationSecret();
        const app_cipher = try Cipher.initTls13(h.cipher_suite, application_secret, .server);
        // set application cipher instead of EndOfStream error
        h.readClientFlight2(opt) catch |err| {
            if (err != error.EndOfStream and err != error.InputBufferUndersize) {
                // don't change on short reads: https://github.com/ianic/tls.zig/commit/2f3f23485e01e4be8219c4a1ceda01ed961da61d
                h.cipher = app_cipher;
            }
            return err;
        };
        h.cipher = app_cipher;
    }

    fn serverFlight(h: *Self, opt: Options) !void {
        // Refuse-unmatched-SNI hook (rejectNoMatch). When the caller
        // refuses to serve any cert for the presented SNI, the engine
        // emits an unrecognized_name alert before any post-ClientHello
        // flight bytes hit the wire.
        if (h.no_match_abort) return error.TlsUnrecognizedName;

        // Phase 1b.24 — per-host ALPN override no-overlap: setAuth()
        // found no intersection between the per-host alpn_protocols and
        // the client's offered list. Surface the same error that
        // readClientHello would have raised on the inline path.
        if (h.alpn_no_match) return error.TlsNoApplicationProtocol;

        var w: record.Writer = .initFromIo(h.output);

        const shared_key = brk: {
            var seed: [DhKeyPair.seed_len]u8 = undefined;
            opt.rng.bytes(&seed);
            var kp = try DhKeyPair.init(seed, &[_]proto.NamedGroup{h.named_group});
            h.server_pub_key = try common.dupe(&h.server_pub_key_buf, try kp.publicKey(h.named_group));
            break :brk try kp.sharedKey(h.named_group, h.client_pub_key);
        };
        {
            const hello = try h.makeServerHello(&w);
            h.transcript.update(hello[record.header_len..]);
        }
        {
            const handshake_secret = h.transcript.handshakeSecret(shared_key);
            h.cipher = try Cipher.initTls13(h.cipher_suite, handshake_secret, .server);
        }
        try w.record(.change_cipher_spec, &[_]u8{1});
        {
            var hw = try w.writerAdvance(record.header_len);
            if (h.alpn_protocol) |selected| {
                // EncryptedExtensions with ALPN
                // Build the extensions payload first
                const proto_len: u16 = @intCast(selected.len);
                const alpn_ext_len = 2 + 2 + 2 + 1 + proto_len; // ext_type(2) + ext_len(2) + list_len(2) + proto_len_byte(1) + proto
                const ee_header_pos = try hw.skip(4); // handshake header placeholder
                try hw.int(u16, alpn_ext_len); // extensions length
                try hw.alpn(&.{selected});
                var hdr_w = hw.writerAt(ee_header_pos);
                try hdr_w.handshakeRecordHeader(.encrypted_extensions, hw.pos() - ee_header_pos - 4);
            } else {
                try hw.handshakeRecord(.encrypted_extensions, &[_]u8{ 0, 0 });
            }
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }
        if (opt.client_auth) |ca| { // Certificate request
            var hw = try w.writerAdvance(record.header_len);
            try makeCertificateRequest(&hw, ca.cert_authorities_ext_bytes);
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }
        // Read the runtime-resolved auth from `h.opt_auth` (populated
        // either at construction from `opt.auth` by `initWithAllocator`
        // for legacy callers, or via `setAuth()` for SNI dispatch
        // callers). Bit-identical for the legacy path; the indirection
        // just lets SNI vary the cert.
        if (h.opt_auth) |auth| {
            const cb = CertificateBuilder{
                .rng = opt.rng,
                .cert_key_pair = auth,
                .transcript = &h.transcript,
                .side = .server,
                // Phase OCSP-wire — staple only if the client asked AND a
                // staple was supplied via setAuth. Null otherwise → empty
                // leaf extensions (bit-identical legacy).
                .ocsp_staple = if (h.client_requested_ocsp) h.ocsp_staple else null,
            };
            { // Certificate
                var hw = try w.writerAdvance(record.header_len);
                try cb.makeCertificate(&hw);
                h.transcript.update(hw.buffered());
                try h.writeEncrypted(&w, hw.buffered());
            }
            { // Certificate verify
                var hw = try w.writerAdvance(record.header_len);
                try cb.makeCertificateVerify(&hw);
                h.transcript.update(hw.buffered());
                try h.writeEncrypted(&w, hw.buffered());
            }
        }
        { // Finished
            var hw = try w.writerAdvance(record.header_len);
            try hw.handshakeRecord(.finished, h.transcript.serverFinishedTls13());
            h.transcript.update(hw.buffered());
            try h.writeEncrypted(&w, hw.buffered());
        }

        h.output.advance(w.buffered().len);
    }

    fn readClientFlight2(h: *Self, opt: Options) !void {
        // buffer for decrypted handshake records
        var cleartext_buffer: [max_cleartext_len]u8 = undefined;
        // cleartext writer
        var cw = Io.Writer.fixed(&cleartext_buffer);

        var handshake_state: proto.Handshake = .finished;
        var crt_parser: CertificateParser = undefined;
        if (opt.client_auth) |client_auth| {
            // Close the allocator-optional footgun: if a caller
            // configured `Options.client_auth` but constructed the
            // server via the legacy no-allocator `init`, post-handshake
            // cert capture would silently no-op. Fail loudly in debug
            // builds so misuse surfaces at handshake time, not via a
            // confusing `peerCertificate() == null` downstream.
            std.debug.assert(h.allocator != null);
            crt_parser = .{
                .root_ca = client_auth.root_ca,
                .host = "",
                .now_sec = opt.now.toSeconds(),
                // Propagate the defensive chain-depth cap.
                .max_chain_depth = client_auth.max_chain_depth,
            };
            handshake_state = .certificate;
        }

        // Phase 1b.19 — caller-owned stack storage for chain DER slices,
        // sized to the chain-depth cap. The parser fills entries
        // [0..cert_count) inside parseCertificate; the alloc block in
        // the .certificate handler below dupes each into long-lived
        // memory before this stack frame exits.
        //
        // Sized to u8 max (255) — the absolute upper bound of
        // `max_chain_depth` since it's a u8 field. Worst case is
        // `255 * @sizeOf(?[]const u8) = 255 * 16 = 4 KiB` of stack.
        // Acceptable for a function-local buffer.
        //
        // Initialized to all-null so the dupe loop can detect "this
        // index was never filled" via `orelse return error.TlsInternalError`
        // (defensive; should never trip if parseCertificate's loop is
        // correct).
        var chain_storage_array: [255]?[]const u8 = .{null} ** 255;
        if (opt.client_auth) |client_auth| {
            if (client_auth.retain_chain) {
                crt_parser.chain_der_storage = chain_storage_array[0..client_auth.max_chain_depth];
            }
        }

        outer: while (true) {
            const rec = try Record.read(h.input);
            if (rec.protocol_version != .tls_1_2 and rec.content_type != .alert)
                return error.TlsProtocolVersion;

            switch (rec.content_type) {
                .change_cipher_spec => {
                    if (rec.payload.len != 1) return error.TlsUnexpectedMessage;
                },
                .application_data => {
                    const content_type, const cleartext = try h.cipher.decrypt(cw.unusedCapacitySlice(), rec);
                    cw.advance(cleartext.len);

                    var d = record.Decoder.init(content_type, cw.buffered());
                    try d.expectContentType(.handshake);
                    while (!d.eof()) {
                        const handshake_type = try d.decode(proto.Handshake);
                        const length = try d.decode(u24);

                        if (length > max_cleartext_len)
                            return error.TlsRecordOverflow;
                        if (length > d.rest().len)
                            continue :outer; // fragmented handshake into multiple records

                        defer {
                            h.transcript.update(d.payload[0..d.idx]);
                            _ = cw.consume(d.idx);
                            d = record.Decoder.init(content_type, cw.buffered());
                        }

                        if (handshake_state != handshake_type)
                            return error.TlsUnexpectedMessage;

                        switch (handshake_type) {
                            .certificate => {
                                if (length == 4) {
                                    // got empty certificate message
                                    if (opt.client_auth.?.auth_type == .require)
                                        return error.TlsCertificateRequired;
                                    try d.skip(length);
                                    handshake_state = .finished;
                                } else {
                                    try crt_parser.parseCertificate(&d, .tls_1_3);
                                    // Copy the verified leaf DER into
                                    // allocator-owned memory BEFORE the
                                    // stack-local cleartext_buffer (and
                                    // therefore crt_parser.leaf_der) goes
                                    // out of scope. On OOM the handshake
                                    // aborts; `peer_cert_der` stays null
                                    // and the connection tears down
                                    // cleanly via the engine's existing
                                    // alert-from-error machinery.
                                    if (h.allocator) |alloc| {
                                        if (crt_parser.leaf_der) |leaf| {
                                            h.peer_cert_der = try alloc.dupe(u8, leaf);
                                        }
                                        // Phase 1b.19 — additionally dupe
                                        // the full chain when retain_chain
                                        // is set. The storage array on
                                        // crt_parser was filled by
                                        // parseCertificate at indices
                                        // [0..cert_count); each entry is
                                        // a slice into the about-to-die
                                        // cleartext_buffer, so we MUST
                                        // dupe before exiting this scope.
                                        //
                                        // OOM partway through frees what
                                        // we've duped so far via the
                                        // errdefer chain; deinit then
                                        // sees `peer_chain_der == null`
                                        // and the partial-leaf branch
                                        // above is the only state that
                                        // persists. The engine teardown
                                        // surfaces error.OutOfMemory.
                                        if (opt.client_auth.?.retain_chain) {
                                            const slot_count: usize = crt_parser.cert_count;
                                            if (slot_count > 0) {
                                                const owned = try alloc.alloc([]const u8, slot_count);
                                                errdefer alloc.free(owned);
                                                var filled: usize = 0;
                                                errdefer for (owned[0..filled]) |bytes| alloc.free(bytes);
                                                const storage = crt_parser.chain_der_storage orelse unreachable;
                                                var ci: usize = 0;
                                                while (ci < slot_count) : (ci += 1) {
                                                    const slice = storage[ci] orelse return error.TlsInternalError;
                                                    owned[ci] = try alloc.dupe(u8, slice);
                                                    filled += 1;
                                                }
                                                h.peer_chain_der = owned;
                                            }
                                        }
                                    }
                                    handshake_state = .certificate_verify;
                                }
                            },
                            .certificate_verify => {
                                try crt_parser.parseCertificateVerify(&d);
                                crt_parser.verifySignature(h.transcript.clientCertificateVerify()) catch |err| return switch (err) {
                                    error.TlsUnknownSignatureScheme => error.TlsIllegalParameter,
                                    else => error.TlsDecryptError,
                                };
                                handshake_state = .finished;
                            },
                            .finished => {
                                const actual = try d.slice(length);
                                const expected = h.transcript.clientFinishedTls13();
                                if (!mem.eql(u8, expected, actual))
                                    return if (expected.len == actual.len)
                                        error.TlsDecryptError
                                    else
                                        error.TlsDecodeError;
                                return;
                            },
                            else => return error.TlsUnexpectedMessage,
                        }
                    }
                },
                .alert => {
                    var d = record.Decoder.init(rec.content_type, rec.payload);
                    return d.raiseAlert();
                },
                else => return error.TlsUnexpectedMessage,
            }
        }
    }

    /// Write encrypted handshake message into `w` Cleartext and write buffer
    /// `w.unused()` are reusing same buffer. Cleartext is written 5 bytes ahead
    /// (record header len) from w.unused() position to avoid memcopy in the
    /// encrypt. Encrypt will add tls record head in first 5 bytes, encrypt
    /// cleartext and add hmac at end.
    fn writeEncrypted(h: *Self, w: *record.Writer, cleartext: []const u8) !void {
        const ciphertext = try h.cipher.encrypt(w.unused(), .handshake, cleartext);
        w.advance(ciphertext.len);
    }

    fn makeServerHello(h: *Self, w: *record.Writer) ![]const u8 {
        const header_pos = try w.skip(9);

        try w.enumValue(proto.Version.tls_1_2);
        try w.slice(&h.server_random);
        {
            try w.int(u8, h.legacy_session_id.len);
            if (h.legacy_session_id.len > 0) try w.slice(h.legacy_session_id);
        }
        try w.enumValue(h.cipher_suite);
        try w.slice(&[_]u8{0}); // compression method

        const ext_len_pos = try w.skip(2); // extensions length placeholder writer
        { // supported versions extension
            try w.enumValue(proto.Extension.supported_versions);
            try w.int(u16, 2);
            try w.enumValue(proto.Version.tls_1_3);
        }
        { // key share extension
            const key_len: u16 = @intCast(h.server_pub_key.len);
            try w.enumValue(proto.Extension.key_share);
            try w.int(u16, key_len + 4);
            try w.enumValue(h.named_group);
            try w.int(u16, key_len);
            try w.slice(h.server_pub_key);
        }
        var ew = w.writerAt(ext_len_pos);
        try ew.int(u16, w.pos() - ext_len_pos - 2);
        var hw = w.writerAt(header_pos);
        try hw.recordHeader(.handshake, w.pos() - 5);
        try hw.handshakeRecordHeader(.server_hello, w.pos() - 9);

        return w.buffered();
    }

    fn makeCertificateRequest(w: *record.Writer, cert_authorities_ext_bytes: ?[]const u8) !void {
        const header_pos = try w.skip(4 + 1 + 2);
        const ext_head = w.pos();
        try w.extension(.signature_algorithms, common.supported_signature_algorithms);
        // Phase 1b.25 — RFC 8446 §4.2.4 certificate_authorities extension.
        // Caller pre-encodes the entire CertificateAuthorities struct
        // (`<u16 authorities_length><DN list>`); we wrap in the standard
        // TLS extension envelope.
        if (cert_authorities_ext_bytes) |bytes| {
            try w.int(u16, 47); // extension_type = certificate_authorities (0x002F)
            std.debug.assert(bytes.len <= std.math.maxInt(u16));
            try w.int(u16, @as(u16, @intCast(bytes.len))); // ext_data length
            try w.slice(bytes); // verbatim payload — library is opaque to semantics
        }
        const ext_len = w.pos() - ext_head;
        var hw = w.writerAt(header_pos);
        try hw.handshakeRecordHeader(.certificate_request, ext_len + 3);
        try hw.int(u8, 0); // certificate request context length = 0
        try hw.int(u16, ext_len); // extensions length
    }

    fn readClientHello(h: *Self, supported_cipher_suites: []const CipherSuite, server_alpn_protocols: []const []const u8) !void {
        var d = try Record.decoder(h.input);
        if (d.payload.len > max_cleartext_len) return error.TlsRecordOverflow;
        try d.expectContentType(.handshake);
        h.transcript.update(d.payload);

        const handshake_type = try d.decode(proto.Handshake);
        if (handshake_type != .client_hello) return error.TlsUnexpectedMessage;
        _ = try d.decode(u24); // handshake length
        if (try d.decode(proto.Version) != .tls_1_2) return error.TlsProtocolVersion;

        h.client_random = try d.array(32);
        { // legacy session id
            const len = try d.decode(u8);
            h.legacy_session_id = try common.dupe(&h.legacy_session_id_buf, try d.slice(len));
        }
        { // cipher suites
            const end_idx = try d.decode(u16) + d.idx;

            while (d.idx < end_idx) {
                const cipher_suite = try d.decode(CipherSuite);
                if (cipher_suites.includes(supported_cipher_suites, cipher_suite) and
                    @intFromEnum(h.cipher_suite) == 0)
                {
                    h.cipher_suite = cipher_suite;
                }
            }
            if (@intFromEnum(h.cipher_suite) == 0)
                return error.TlsNoSupportedCiphers;
        }
        try d.skip(2); // compression methods

        var key_share_received = false;
        // extensions
        const extensions_end_idx = try d.decode(u16) + d.idx;
        while (d.idx < extensions_end_idx) {
            const extension_type = try d.decode(proto.Extension);
            const extension_len = try d.decode(u16);

            switch (extension_type) {
                .supported_versions => {
                    var tls_1_3_supported = false;
                    const end_idx = try d.decode(u8) + d.idx;
                    while (d.idx < end_idx) {
                        if (try d.decode(proto.Version) == proto.Version.tls_1_3) {
                            tls_1_3_supported = true;
                        }
                    }
                    if (!tls_1_3_supported) return error.TlsProtocolVersion;
                },
                .key_share => {
                    if (extension_len == 0) return error.TlsDecodeError;
                    key_share_received = true;
                    var selected_named_group_idx = supported_named_groups.len;
                    const end_idx = try d.decode(u16) + d.idx;
                    while (d.idx < end_idx) {
                        const named_group = try d.decode(proto.NamedGroup);
                        switch (@intFromEnum(named_group)) {
                            0x0001...0x0016,
                            0x001a...0x001c,
                            0xff01...0xff02,
                            => return error.TlsIllegalParameter,
                            else => {},
                        }
                        const client_pub_key = try d.slice(try d.decode(u16));
                        for (supported_named_groups, 0..) |supported, idx| {
                            if (named_group == supported and idx < selected_named_group_idx) {
                                h.named_group = named_group;
                                h.client_pub_key = try common.dupe(&h.client_pub_key_buf, client_pub_key);
                                selected_named_group_idx = idx;
                            }
                        }
                    }
                    if (@intFromEnum(h.named_group) == 0)
                        return error.TlsIllegalParameter;
                },
                .supported_groups => {
                    const end_idx = try d.decode(u16) + d.idx;
                    while (d.idx < end_idx) {
                        const named_group = try d.decode(proto.NamedGroup);
                        switch (@intFromEnum(named_group)) {
                            0x0001...0x0016,
                            0x001a...0x001c,
                            0xff01...0xff02,
                            => return error.TlsIllegalParameter,
                            else => {},
                        }
                    }
                },
                .signature_algorithms => {
                    // Cache the client's offered signature schemes so
                    // we can validate the post-`setAuth` resolved cert's
                    // signature scheme later (SNI dispatch path).
                    // Legacy path (signature_scheme already set by
                    // initKeys from pinned opt.auth) still validates
                    // inline.
                    const list_len = try d.decode(u16);
                    if (list_len == 0) return error.TlsDecodeError;
                    const end_idx = list_len + d.idx;
                    var found = false;
                    while (d.idx < end_idx) {
                        const signature_scheme = try d.decode(proto.SignatureScheme);
                        // Cache with a defensive buffer cap; truncating
                        // is fine — we only need enough schemes to
                        // validate against, and 64 is well above any
                        // real ClientHello.
                        if (h.client_signature_schemes_len < h.client_signature_schemes_buf.len) {
                            h.client_signature_schemes_buf[h.client_signature_schemes_len] = signature_scheme;
                            h.client_signature_schemes_len += 1;
                        }
                        if (@intFromEnum(h.signature_scheme) != 0 and
                            signature_scheme == h.signature_scheme)
                        {
                            found = true;
                        }
                    }
                    if (@intFromEnum(h.signature_scheme) != 0 and !found) {
                        return error.TlsHandshakeFailure;
                    }
                },
                .server_name => {
                    // RFC 6066 §3 ServerNameList. Each ServerName has a
                    // NameType (u8); body length is DEFINED ONLY for
                    // NameType.host_name(0) (uint16-prefixed HostName).
                    // For unknown NameTypes, RFC 6066 does NOT define a
                    // wire-level length prefix — generic skip is unsafe
                    // (we'd consume bytes that aren't length-prefixed
                    // and catastrophically mis-align). Algorithm:
                    //   - Walk entries.
                    //   - On NameType.host_name(0): parse u16 len +
                    //     bytes. First host_name wins (defensive against
                    //     malicious duplicate hostnames). Malformed
                    //     entry (zero-length, > 255 bytes, body
                    //     overrun) → treat SNI as absent (don't error
                    //     the handshake).
                    //   - On any other NameType: STOP parsing the list
                    //     (cannot advance safely). SNI is whatever
                    //     host_name was seen before this point
                    //     (typically none → sni_host_len stays 0).
                    // Malformed list-level lengths flow through the
                    // existing decoder's error path.
                    const list_len_u16 = try d.decode(u16);
                    const list_end = list_len_u16 + d.idx;
                    if (list_end > d.payload.len) return error.TlsDecodeError;
                    while (d.idx < list_end) {
                        const name_type = try d.decode(u8);
                        if (name_type != 0) {
                            // Unknown NameType — stop parsing.
                            break;
                        }
                        const name_len = try d.decode(u16);
                        if (name_len == 0 or name_len > 255 or d.idx + name_len > list_end) {
                            // Malformed host_name entry — treat SNI as
                            // absent. Clear any previously-captured
                            // host_name to match the "first-malformed-
                            // wins-absent" semantic — defensive against
                            // attackers crafting a valid+malformed pair.
                            h.sni_host_len = 0;
                            const remaining = list_end - d.idx;
                            try d.skip(remaining);
                            break;
                        }
                        const bytes = try d.slice(name_len);
                        if (h.sni_host_len == 0) {
                            // First host_name wins.
                            @memcpy(h.sni_host_buf[0..name_len], bytes);
                            h.sni_host_len = @intCast(name_len);
                        }
                    }
                    // If we broke out early on an unknown NameType, skip
                    // any remaining bytes in the extension body to keep
                    // the outer decoder aligned with extension_len.
                    if (d.idx < list_end) {
                        try d.skip(list_end - d.idx);
                    }
                },
                .application_layer_protocol_negotiation => {
                    // RFC 7301: parse client ALPN extension and select a protocol.
                    //
                    // Phase 1b.24: when the server has a non-empty
                    // `server_alpn_protocols` list, capture the raw client
                    // protocol list bytes into `h.client_alpn_list_buf`. This
                    // lets `setAuth()` re-run ALPN selection when a per-host
                    // `alpn_protocols` override is supplied after the
                    // ClientHello has already been consumed. The outer
                    // list_len u16 is decoded first (to advance past it); we
                    // then copy the list content (length-prefixed protocol
                    // names) into the inline buffer.
                    //
                    // When `server_alpn_protocols.len == 0` (listener has no
                    // ALPN configured), we skip past the client's list without
                    // copying — preserving the no-cost-when-not-used invariant.
                    const list_len_u16 = try d.decode(u16);
                    const list_start = d.idx;
                    if (list_start + list_len_u16 > d.payload.len) return error.TlsDecodeError;
                    const list_end = list_start + list_len_u16;

                    if (server_alpn_protocols.len > 0) {
                        // C1: Reject oversized client ALPN list. 512 bytes is
                        // well above any realistic ClientHello ALPN list
                        // (typical: "h2"=2, "http/1.1"=9 each prefixed by
                        // 1-byte length → rarely exceeds 64 bytes). A list
                        // larger than the buffer would require truncation,
                        // which would allow a malicious client to push real
                        // protocol matches into the truncated tail, forcing a
                        // spurious "no match" verdict in setAuth().
                        if (list_len_u16 > h.client_alpn_list_buf.len) return error.TlsDecodeError;
                        const to_copy = list_len_u16;
                        @memcpy(h.client_alpn_list_buf[0..to_copy], d.payload[list_start .. list_start + to_copy]);
                        h.client_alpn_list_len = to_copy;

                        // Find the first server protocol that the client supports
                        // (server preference order).
                        var best_match: ?[]const u8 = null;
                        var best_server_idx: usize = server_alpn_protocols.len;
                        const saved_idx = d.idx;
                        for (server_alpn_protocols, 0..) |server_proto, si| {
                            d.idx = saved_idx;
                            while (d.idx < list_end) {
                                const proto_len = try d.decode(u8);
                                const client_proto = try d.slice(proto_len);
                                if (si < best_server_idx and mem.eql(u8, client_proto, server_proto)) {
                                    best_match = server_proto;
                                    best_server_idx = si;
                                }
                            }
                        }
                        d.idx = list_end;
                        h.alpn_protocol = best_match;
                        if (best_match == null) {
                            return error.TlsNoApplicationProtocol;
                        }
                    } else {
                        // Server has no ALPN list configured — skip past
                        // the client's list without selecting or copying
                        // anything. `client_alpn_list_len` stays at its
                        // default 0; `setAuth()`'s override path correctly
                        // handles "no captured client list" by clearing
                        // `alpn_protocol`.
                        try d.skip(list_len_u16);
                    }
                },
                .status_request => {
                    // RFC 6066 §8: the client's CertificateStatusRequest.
                    // We only need to know it was sent (server preference
                    // is to staple if asked); the body is not inspected.
                    // Skip the same bytes the `else` arm would have.
                    h.client_requested_ocsp = true;
                    try d.skip(extension_len);
                },
                else => {
                    try d.skip(extension_len);
                },
            }
        }
        if (!key_share_received) return error.TlsMissingExtension;
        if (@intFromEnum(h.named_group) == 0) return error.TlsIllegalParameter;
    }
};

const testing = std.testing;
const data13 = @import("testdata/tls13.zig");
const testu = @import("testu.zig");

test "read client hello" {
    var reader: Io.Reader = .fixed(&data13.client_hello);
    var h: Handshake = .{
        .input = &reader,
        .output = undefined,
    };
    h.signature_scheme = .ecdsa_secp521r1_sha512; // this must be supported in signature_algorithms extension
    try h.readClientHello(cipher_suites.tls13, &.{});

    try testing.expectEqual(CipherSuite.AES_256_GCM_SHA384, h.cipher_suite);
    try testing.expectEqual(.x25519, h.named_group);
    try testing.expectEqualSlices(u8, &data13.client_random, &h.client_random);
    try testing.expectEqualSlices(u8, &data13.client_public_key, h.client_pub_key);
}

test "make server hello" {
    var h: Handshake = .{ .input = undefined, .output = undefined };

    h.cipher_suite = .AES_256_GCM_SHA384;
    testu.fillFrom(&h.server_random, 0);
    testu.fillFrom(&h.server_pub_key_buf, 0x20);
    h.named_group = .x25519;
    h.server_pub_key = h.server_pub_key_buf[0..32];

    const expected = &testu.hexToBytes(
        \\ 16 03 03 00 5a 02 00 00 56
        \\ 03 03
        \\ 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        \\ 00
        \\ 13 02 00
        \\ 00 2e 00 2b 00 02 03 04
        \\ 00 33 00 24 00 1d 00 20
        \\ 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
    );

    var buffer: [128]u8 = undefined;
    var w: record.Writer = .init(&buffer);
    const actual = try h.makeServerHello(&w);
    try testing.expectEqual(95, actual.len);
    try testing.expectEqualSlices(u8, expected, actual);
}

test "make certificate request" {
    var buffer: [32]u8 = undefined;

    const expected = testu.hexToBytes("0d 00 00 1b" ++ // handshake header
        "00 00 18" ++ // extension length
        "00 0d" ++ // signature algorithms extension
        "00 14" ++ // extension length
        "00 12" ++ // list length 6 * 2 bytes
        "04 03 05 03 08 04 08 05 08 06 08 07 02 01 04 01 05 01" // signature schemes
    );

    var w: record.Writer = .init(&buffer);
    try Handshake.makeCertificateRequest(&w, null);
    try testing.expectEqualSlices(u8, &expected, w.buffered());
}

test "OCSP-wire — readClientHello leaves client_requested_ocsp false when status_request absent" {
    // data13.client_hello has no status_request extension; flag must stay false.
    var reader: Io.Reader = .fixed(&data13.client_hello);
    var h: Handshake = .{ .input = &reader, .output = undefined };
    h.signature_scheme = .ecdsa_secp521r1_sha512;
    try h.readClientHello(cipher_suites.tls13, &.{});
    try testing.expect(!h.client_requested_ocsp);
}

pub const NonBlock = struct {
    const Self = @This();

    // inner sync handshake
    inner: Handshake = undefined,
    opt: Options = undefined,
    state: State = undefined,

    /// Internal state machine. The `awaiting_auth` variant sits between
    /// `client_flight_1` (ClientHello consumed) and `server_flight`
    /// (ServerHello emit). When the caller constructed `NonBlock.Server`
    /// with `opt.auth = null`, `run()` returns `.awaiting_auth` after
    /// `readClientHello`. The caller inspects `sniHost()`, calls
    /// `setAuth()` or `rejectNoMatch()`, then re-invokes `run()` to
    /// proceed.
    ///
    /// Legacy callers (`Options.auth` set at construction):
    /// `initWithAllocator` populates `inner.opt_auth` and sets
    /// `inner.auth_resolved = true`, so `run()` skips `awaiting_auth`
    /// entirely. Bit-identical legacy behavior.
    const State = enum {
        init,
        client_flight_1,
        awaiting_auth,
        server_flight,
        client_flight_2,

        fn next(self: *State) void {
            self.* = @enumFromInt(@intFromEnum(self.*) + 1);
        }
    };

    /// Observable state surfaced from `runState()`. Maps the internal
    /// State enum to a 3-way contract callers can switch on:
    ///   .in_progress — engine has more work; caller pushes more
    ///                  ciphertext via `run()` (legacy behavior).
    ///   .awaiting_auth — ClientHello has been consumed; caller MUST
    ///                    call setAuth() or rejectNoMatch() before
    ///                    invoking run() again. Returned exactly once
    ///                    per SNI-dispatch handshake.
    ///   .done — handshake complete.
    pub const RunState = enum {
        in_progress,
        awaiting_auth,
        done,
    };

    /// Observe the current state machine position. Returns
    /// `.awaiting_auth` only when the engine has consumed ClientHello
    /// AND the caller has not yet resolved auth via `setAuth()` or
    /// `rejectNoMatch()`. Otherwise reports `.in_progress` or `.done`
    /// mirroring `done()`.
    pub fn runState(self: Self) RunState {
        if (self.done()) return .done;
        if (self.state == .awaiting_auth and !self.inner.auth_resolved) return .awaiting_auth;
        return .in_progress;
    }

    /// Resolve the auth and advance past the `.awaiting_auth` pause.
    /// `cert_key_pair` MUST be a valid pointer; the engine emits
    /// Certificate using it on the next `run()`. The pointee is treated
    /// as read-only — the library never mutates a `CertKeyPair`, so the
    /// `*const` lets callers stash a single shared pair in a dispatch
    /// table behind `*const`. After `setAuth`, the post-resolution
    /// `signature_scheme` is validated against the client's offered
    /// `signature_algorithms` list (cached during `readClientHello`) —
    /// mismatch trips `error.TlsHandshakeFailure` on the next `run()`.
    ///
    /// Phase 1b.24 — extended with two optional per-host override params:
    ///
    ///   `client_auth`     — when non-null, REPLACES `Options.client_auth`
    ///                       on this NonBlock.Server before the next run().
    ///                       The replacement takes effect before
    ///                       CertificateRequest emission in `serverFlight`.
    ///                       Null preserves the value in `Options` (backward-
    ///                       compatible with pre-1b.24 callers).
    ///
    ///   `alpn_protocols`  — when non-null, re-runs ALPN selection using
    ///                       the supplied list against the client's offered
    ///                       protocols (cached from `readClientHello`).
    ///                       The result overwrites `inner.alpn_protocol`
    ///                       BEFORE EncryptedExtensions emission. Null
    ///                       preserves the selection already made during
    ///                       `readClientHello` (backward-compatible).
    ///
    ///   `ocsp_staple`     — Phase OCSP-wire. When non-null, a raw
    ///                       `OCSPResponse` DER blob to staple into the
    ///                       leaf `CertificateEntry` (RFC 6066 §8 /
    ///                       RFC 8446 §4.4.2). The library never copies,
    ///                       frees, or inspects these bytes; the caller
    ///                       owns the lifetime. The staple is emitted ONLY
    ///                       when the client also requested OCSP via
    ///                       `status_request`; if the client did not
    ///                       request it the bytes are ignored. Null = no
    ///                       staple.
    ///
    /// Idempotency: when called a second time after `auth_resolved` is set,
    /// re-stamps `cert_key_pair` and `ocsp_staple`; other params ignored.
    /// This protects against any future state-machine bug that
    /// re-enters `.awaiting_auth` after a valid resolution.
    pub fn setAuth(
        self: *Self,
        cert_key_pair: *const CertKeyPair,
        client_auth: ?ClientAuth,
        alpn_protocols: ?[]const []const u8,
        ocsp_staple: ?[]const u8,
    ) void {
        // Idempotency guard: if we've already resolved auth (e.g. a buggy
        // double-call) re-stamp the cert but leave everything else alone.
        // The engine's state machine gates on `auth_resolved`; once it's
        // true the handshake proceeds unconditionally on the next run().
        if (self.inner.auth_resolved) {
            self.inner.opt_auth = cert_key_pair;
            self.inner.ocsp_staple = ocsp_staple;
            return;
        }

        self.inner.opt_auth = cert_key_pair;
        self.inner.ocsp_staple = ocsp_staple;

        // Per-host client_auth override — applied BEFORE serverFlight
        // consults `opt.client_auth` to decide whether to emit
        // CertificateRequest. Non-null replaces; null = preserve Options.
        if (client_auth) |ca| {
            self.opt.client_auth = ca;
        }

        // Per-host ALPN override — re-run selection against the cached
        // client offer (captured in `readClientHello`).  Non-null
        // overrides the already-selected `inner.alpn_protocol`; null
        // preserves the selection made in readClientHello.
        //
        // If the client sent no ALPN extension OR the override list is
        // empty, clear `inner.alpn_protocol` (no ALPN response). If the
        // client offered protocols but none overlap with the override
        // list, set the no_alpn_match flag so serverFlight can surface
        // `error.TlsNoApplicationProtocol` — matching the behavior of
        // the inline ALPN path in readClientHello.
        if (alpn_protocols) |override| {
            // C2: Reset before running override selection so this branch
            // always starts from a known-clean state. The write `= true`
            // on failure (or the implicit `false` on success) below keeps
            // the invariant regardless of prior state.
            self.inner.alpn_no_match = false;
            if (self.inner.client_alpn_list_len == 0 or override.len == 0) {
                // Client sent no ALPN, or override is empty — no selection.
                self.inner.alpn_protocol = null;
            } else {
                // Re-run selection: iterate override list in preference
                // order, pick the first protocol the client also offered.
                const raw = self.inner.client_alpn_list_buf[0..self.inner.client_alpn_list_len];
                var best: ?[]const u8 = null;
                outer: for (override) |srv_proto| {
                    var pos: usize = 0;
                    while (pos < raw.len) {
                        const plen = raw[pos];
                        pos += 1;
                        if (pos + plen > raw.len) break; // malformed — stop
                        const cli_proto = raw[pos .. pos + plen];
                        pos += plen;
                        if (mem.eql(u8, cli_proto, srv_proto)) {
                            best = srv_proto;
                            break :outer;
                        }
                    }
                }
                self.inner.alpn_protocol = best;
                self.inner.alpn_no_match = (best == null);
            }
        }

        self.inner.auth_resolved = true;
    }

    /// Refuse the handshake with TLS alert `unrecognized_name(112)` per
    /// RFC 6066 §3. The lib's existing alert-from-error machinery
    /// translates the error raised in `serverFlight`.
    pub fn rejectNoMatch(self: *Self) void {
        self.inner.no_match_abort = true;
        self.inner.auth_resolved = true;
    }

    pub fn init(opt: Options) Self {
        // Back-compat entry point. No allocator → no leaf DER capture.
        // All pre-mTLS-capture callers continue to compile and run
        // bit-identically against this overload.
        return initWithAllocator(opt, null);
    }

    /// Allocator-aware constructor. When `allocator` is non-null AND
    /// `opt.client_auth` is non-null, the engine captures the verified
    /// peer's leaf certificate DER into allocator-owned memory during
    /// `readClientFlight2`. The copy is freed by `deinit`. Callers
    /// retrieve it via `peerCertificate()` after `done()` returns true.
    ///
    /// Passing `null` is equivalent to calling `init` — no leaf capture,
    /// no allocation.
    pub fn initWithAllocator(opt: Options, allocator: ?std.mem.Allocator) Self {
        var inner: Handshake = .{
            .input = undefined,
            .output = undefined,
            .allocator = allocator,
        };
        // Legacy back-compat path: when the caller constructed Options
        // with `auth` non-null OR null (server-without-cert mode), mark
        // `auth_resolved = true` so the new awaiting_auth pause is
        // never entered. Bit-identical existing behavior. SNI dispatch
        // callers MUST use `initForSniDispatch` to opt into the pause.
        if (opt.auth) |a| {
            inner.opt_auth = a;
        }
        inner.auth_resolved = true;
        inner.initKeys(opt);
        return .{
            .opt = opt,
            .inner = inner,
            .state = .init,
        };
    }

    /// SNI-dispatch constructor. Constructs a `NonBlock.Server` that
    /// pauses after consuming the ClientHello so the caller can inspect
    /// `sniHost()` and pick a cert via `setAuth()` (or refuse via
    /// `rejectNoMatch()`).
    ///
    /// `opt.auth` MUST be null on entry (the caller will supply the
    /// auth via `setAuth()`); a non-null `opt.auth` would shadow the
    /// resolved cert. `allocator` may be null when the caller does not
    /// need to capture the peer's client certificate (no mTLS).
    ///
    /// Workflow:
    ///   1. Construct via `initForSniDispatch(opt, allocator)`.
    ///   2. Call `run(...)`. When `runState() == .awaiting_auth`,
    ///      inspect `sniHost()` and invoke either `setAuth(*ckp)` or
    ///      `rejectNoMatch()`.
    ///   3. Call `run(...)` again — proceeds through ServerHello and
    ///      the rest of the handshake.
    pub fn initForSniDispatch(opt: Options, allocator: ?std.mem.Allocator) Self {
        std.debug.assert(opt.auth == null);
        var inner: Handshake = .{
            .input = undefined,
            .output = undefined,
            .allocator = allocator,
        };
        // auth_resolved stays false → run() pauses at awaiting_auth
        // after readClientHello; caller invokes setAuth() to populate
        // opt_auth before continuing.
        inner.initKeys(opt);
        return .{
            .opt = opt,
            .inner = inner,
            .state = .init,
        };
    }

    /// Release the allocator-owned leaf DER copy if one was captured.
    /// Safe to call when no copy was made (null check). Safe to call
    /// multiple times: clears `peer_cert_der` after free. Calling on a
    /// no-allocator instance is a no-op.
    pub fn deinit(self: *Self) void {
        // Allocator MUST be non-null if we have an owned copy — both
        // peer_cert_der and peer_chain_der are populated inside the
        // same `if (h.allocator)` guard in readClientFlight2. If the
        // allocator field is unexpectedly null but a copy exists, null
        // the field so subsequent calls are no-ops.
        const alloc = self.inner.allocator orelse {
            self.inner.peer_cert_der = null;
            self.inner.peer_chain_der = null;
            return;
        };
        if (self.inner.peer_cert_der) |bytes| {
            alloc.free(bytes);
            self.inner.peer_cert_der = null;
        }
        // Phase 1b.19 — free the chain slices + the slice-of-slices
        // when retain_chain populated it. Each entry is its own dupe;
        // the slice-of-slices is its own allocator.alloc.
        if (self.inner.peer_chain_der) |chain| {
            for (chain) |bytes| alloc.free(bytes);
            alloc.free(chain);
            self.inner.peer_chain_der = null;
        }
    }

    /// Accessor for the verified peer's leaf DER bytes. Returns null in
    /// these cases:
    ///   - handshake has not yet completed (`done() == false`),
    ///   - allocator was null at construction (back-compat path),
    ///   - mTLS not configured (`opt.client_auth == null`),
    ///   - client presented an empty Certificate in `.request` mode.
    ///
    /// The returned slice is owned by this `NonBlock.Server`; lifetime
    /// equals server lifetime (freed by `deinit`). Callers that need
    /// longer retention MUST copy into their own storage.
    pub fn peerCertificate(self: *const Self) ?[]const u8 {
        if (!self.done()) return null;
        return self.inner.peerCertificate();
    }

    /// Phase 1b.19 — accessor for the verified peer's full chain DER
    /// bytes (leaf at index 0). Returns null when:
    ///   - handshake has not yet completed (`done() == false`),
    ///   - allocator was null at construction,
    ///   - mTLS not configured,
    ///   - client presented an empty Certificate flight in `.request`
    ///     mode,
    ///   - `Options.client_auth.?.retain_chain` was false.
    ///
    /// Lifetime equals the owning `NonBlock.Server` (freed by `deinit`).
    pub fn peerChain(self: *const Self) ?[]const []const u8 {
        if (!self.done()) return null;
        return self.inner.peerChain();
    }

    /// Accessor for the parsed SNI hostname from the client's
    /// ClientHello. Forwards to `Handshake.sniHost()`. Returns null
    /// when SNI was absent, malformed, or zero-length. The returned
    /// slice is pinned to the `Handshake` lifetime (inline buffer;
    /// not a slice into the input buffer).
    pub fn sniHost(self: *const Self) ?[]const u8 {
        return self.inner.sniHost();
    }

    /// Phase OCSP-wire — did the client send a `status_request` extension?
    /// Valid after the ClientHello has been consumed (i.e. once the engine
    /// is at `.awaiting_auth` or later). Used by the caller's must-staple
    /// gate before `setAuth`.
    pub fn clientRequestedOcsp(self: *const Self) bool {
        return self.inner.client_requested_ocsp;
    }

    fn recv(self: *Self) !void {
        const prev: Transcript = self.inner.transcript;
        errdefer self.inner.transcript = prev;

        switch (self.state) {
            .init => {
                try self.inner.clientFlight1(self.opt);
                // Branch on auth_resolved. Legacy callers (opt.auth
                // non-null at construction): initWithAllocator already
                // set auth_resolved = true, so we advance to
                // .client_flight_1 (ServerHello emit) — bit-identical
                // legacy behavior. SNI-dispatch callers (opt.auth null
                // at construction): auth_resolved is false; advance to
                // .awaiting_auth so the next run() returns control to
                // the caller. The caller invokes setAuth() (which flips
                // auth_resolved true) before calling run() again.
                if (self.inner.auth_resolved) {
                    self.state = .client_flight_1;
                } else {
                    self.state = .awaiting_auth;
                }
            },
            .server_flight => {
                try self.inner.clientFlight2(self.opt);
                self.state.next();
            },
            else => return,
        }
    }

    /// True when handshake is successfully finished
    pub fn done(self: Self) bool {
        return self.state == .client_flight_2;
    }

    /// Runs next handshake step.
    pub fn run(
        self: *Self,
        /// Data received from the peer
        recv_buf: []const u8,
        /// Scratch buffer where data to be sent to the peer will be prepared
        send_buf: []u8,
    ) !struct {
        /// Number of bytes consumed from recv_buf
        recv_pos: usize,
        /// Number of bytes prepared in send_buf
        send_pos: usize,
        /// Unused part of the recv_buf,
        unused_recv: []const u8,
        /// Part of the send_buf that should be sent to the peer
        send: []const u8,
    } {
        if (self.done()) return .{
            .recv_pos = 0,
            .send_pos = 0,
            .unused_recv = &.{},
            .send = &.{},
        };

        var reader: Io.Reader = .fixed(recv_buf);
        self.inner.input = &reader;
        var writer: Io.Writer = .fixed(send_buf);
        self.inner.output = &writer;

        var recv_pos: usize = 0;
        out: switch (self.state) {
            .init, .server_flight => {
                self.recv() catch |err| switch (err) {
                    error.EndOfStream, error.InputBufferUndersize => {
                        return .{
                            .recv_pos = 0,
                            .send_pos = 0,
                            .unused_recv = recv_buf,
                            .send = &.{},
                        };
                    },
                    else => return err,
                };
                recv_pos = reader.seek;
                continue :out self.state;
            },
            .awaiting_auth => {
                // SNI dispatch pause. The caller is expected to inspect
                // `sniHost()`, choose a cert via their dispatch table,
                // and invoke `setAuth()` BEFORE calling run() again.
                // Once setAuth() flips auth_resolved to true, we
                // transition to .client_flight_1 and proceed to emit
                // ServerHello.
                if (!self.inner.auth_resolved) {
                    // Caller hasn't resolved yet — return control. recv_pos
                    // may be non-zero (ClientHello bytes were consumed in
                    // `.init` above); send is empty.
                    return .{
                        .recv_pos = recv_pos,
                        .send_pos = writer.end,
                        .unused_recv = recv_buf[recv_pos..],
                        .send = writer.buffered(),
                    };
                }
                // setAuth was called — finalize signature scheme +
                // validate against the cached client offer.
                try self.inner.finalizeAuthAndValidateSigScheme();
                self.state = .client_flight_1;
                continue :out self.state;
            },
            .client_flight_1 => {
                if (recv_buf.ptr == send_buf.ptr and recv_pos != recv_buf.len) {
                    // recv buffer is fully consumed, same buffer can be used for write
                    return error.TlsUnexpectedMessage;
                }
                try self.inner.serverFlight(self.opt);
                // Advance directly to .server_flight (skipping the
                // .awaiting_auth slot since we may have entered via
                // either the legacy path or post-setAuth path; in
                // either case auth is resolved and we need to wait for
                // the client's flight 2 next).
                self.state = .server_flight;
            },
            .client_flight_2 => {
                // done
            },
        }

        return .{
            .recv_pos = recv_pos,
            .send_pos = writer.end,
            .unused_recv = recv_buf[recv_pos..],
            .send = writer.buffered(),
        };
    }

    /// Cipher produced in handshake, null until successful handshake.
    pub fn cipher(self: Self) ?Cipher {
        return if (self.done()) self.inner.cipher else null;
    }

    /// ALPN protocol negotiated during handshake, null if none.
    pub fn alpnProtocol(self: Self) ?[]const u8 {
        return self.inner.alpn_protocol;
    }
};

// =====================================================================
// Tests for the mTLS post-handshake identity (peerCertificate) + SNI
// dispatch (sniHost / setAuth / rejectNoMatch) hooks.
// =====================================================================

const handshake_client_mod = @import("handshake_client.zig");

const mtls_test_cert_pem = @embedFile("testdata/mtls_test_cert.pem");
const mtls_test_key_pem = @embedFile("testdata/mtls_test_key.pem");
const mtls_chain_root_pem = @embedFile("testdata/mtls_chain_root_cert.pem");
const mtls_chain_leaf_pem = @embedFile("testdata/mtls_chain_leaf_cert.pem");
const mtls_chain_leaf_key_pem = @embedFile("testdata/mtls_chain_leaf_key.pem");

const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;

/// Drives an in-memory TLS 1.3 handshake between a `NonBlock.Client` and
/// a caller-provided `NonBlock.Server`. Returns when both sides are done
/// or after `max_rounds` iterations (whichever comes first).
fn driveHandshake(
    cli: *handshake_client_mod.NonBlock,
    srv: *NonBlock,
    max_rounds: usize,
) !void {
    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_len: usize = 0;
    var cs_len: usize = 0;

    var rounds: usize = 0;
    while (!cli.done() or !srv.done()) : (rounds += 1) {
        if (rounds > max_rounds) return error.HandshakeTooManyRounds;

        if (!cli.done()) {
            const cr = try cli.run(sc_buf[0..sc_len], &cs_buf);
            if (cr.recv_pos > 0) {
                const remaining = sc_len - cr.recv_pos;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, sc_buf[0..remaining], sc_buf[cr.recv_pos..sc_len]);
                }
                sc_len = remaining;
            }
            cs_len = cr.send.len;
        }

        if (!srv.done()) {
            const sr = try srv.run(cs_buf[0..cs_len], &sc_buf);
            if (sr.recv_pos > 0) {
                const remaining = cs_len - sr.recv_pos;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, cs_buf[0..remaining], cs_buf[sr.recv_pos..cs_len]);
                }
                cs_len = remaining;
            }
            sc_len = sr.send.len;
        }
    }
}

// ---------------------------------------------------------------------
// mTLS — peerCertificate lifetime + back-compat
// ---------------------------------------------------------------------

test "peerCertificate returns leaf DER after handshake completes" {
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    // Self-signed P-256 cert (CA:TRUE, valid until 2100) reused as both
    // server cert AND trust anchor AND client cert — the cert is its
    // own root, so a chain of one is valid.
    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth,
    });
    var srv = NonBlock.initWithAllocator(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
        .client_auth = .{
            .root_ca = root_ca,
            .auth_type = .require,
        },
    }, alloc);
    defer srv.deinit();

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());

    // THE LIFETIME-FIX ASSERTION: readClientFlight2 has returned. Its
    // stack-local cleartext_buffer is gone. If the allocator.dupe is
    // omitted, this slice points at garbage.
    const peer_der = srv.peerCertificate();
    try testing.expect(peer_der != null);
    try testing.expect(peer_der.?.len > 0);

    // Verify the bytes byte-match the leaf cert.
    var fixture_bundle = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer fixture_bundle.deinit(alloc);
    var it = fixture_bundle.map.iterator();
    const entry = it.next() orelse return error.NoCertInFixture;
    const offset = entry.value_ptr.*;
    const outer = try Certificate.der.Element.parse(fixture_bundle.bytes.items, offset);
    const expected_der = fixture_bundle.bytes.items[offset..outer.slice.end];

    try testing.expect(peer_der.?.ptr != expected_der.ptr); // it's a copy
    try testing.expectEqualSlices(u8, expected_der, peer_der.?);
}

test "peerCertificate returns null when no allocator is provided" {
    // Legacy back-compat: `init(opt)` without an allocator. We use a
    // server-only handshake (no client_auth) so the allocator-required
    // assert is not tripped.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
    });
    var srv = NonBlock.init(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
    });

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());
    try testing.expect(srv.peerCertificate() == null);
}

test "OOM during peer cert dupe aborts handshake with no leak" {
    const setup_alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(setup_alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(setup_alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(setup_alloc);
    var client_auth = try common.CertKeyPair.fromSlice(setup_alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth.deinit(setup_alloc);
    var root_ca = try cert.fromSlice(setup_alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(setup_alloc);

    // FailingAllocator with fail_index=0 → first allocation fails.
    var failing = std.testing.FailingAllocator.init(setup_alloc, .{ .fail_index = 0 });
    const oom_alloc = failing.allocator();

    var srv = NonBlock.initWithAllocator(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
        .client_auth = .{
            .root_ca = root_ca,
            .auth_type = .require,
        },
    }, oom_alloc);
    defer srv.deinit();
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth,
    });

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_len: usize = 0;
    var cs_len: usize = 0;
    var got_oom = false;
    var rounds: usize = 0;
    while (!cli.done() or !srv.done()) : (rounds += 1) {
        if (rounds > 12) break;
        if (!cli.done()) {
            const cr = cli.run(sc_buf[0..sc_len], &cs_buf) catch break;
            if (cr.recv_pos > 0) {
                const remaining = sc_len - cr.recv_pos;
                if (remaining > 0) std.mem.copyForwards(u8, sc_buf[0..remaining], sc_buf[cr.recv_pos..sc_len]);
                sc_len = remaining;
            }
            cs_len = cr.send.len;
        }
        if (!srv.done()) {
            const sr = srv.run(cs_buf[0..cs_len], &sc_buf) catch |e| {
                if (e == error.OutOfMemory) {
                    got_oom = true;
                    break;
                }
                return e;
            };
            if (sr.recv_pos > 0) {
                const remaining = cs_len - sr.recv_pos;
                if (remaining > 0) std.mem.copyForwards(u8, cs_buf[0..remaining], cs_buf[sr.recv_pos..cs_len]);
                cs_len = remaining;
            }
            sc_len = sr.send.len;
        }
    }

    try testing.expect(got_oom);
    try testing.expect(srv.peerCertificate() == null);
    // No leak — the failed dupe never committed anything through oom_alloc.
    try testing.expectEqual(failing.allocations, failing.deallocations);
}

test "chain-depth cap accepts in-bounds chain" {
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // max_chain_depth = 4 + client sends 1 cert → loop accepts (1 <= 4).
    var srv = NonBlock.initWithAllocator(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
        .client_auth = .{
            .root_ca = root_ca,
            .auth_type = .require,
            .max_chain_depth = 4,
        },
    }, alloc);
    defer srv.deinit();
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth,
    });

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());
    try testing.expect(srv.peerCertificate() != null);
}

// ---------------------------------------------------------------------
// Phase 1b.19 — chain bytes retention (retain_chain opt-in)
// ---------------------------------------------------------------------

test "peerChain returns null when retain_chain is off (default)" {
    // Bit-identical pre-1b.19 path verification. mTLS .require with the
    // default retain_chain=false → peerChain() stays null even though
    // peerCertificate() is populated.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var srv = NonBlock.initWithAllocator(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
        .client_auth = .{
            .root_ca = root_ca,
            .auth_type = .require,
            // retain_chain omitted → defaults to false
        },
    }, alloc);
    defer srv.deinit();
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth,
    });

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());
    try testing.expect(srv.peerCertificate() != null); // 1b.13 still works
    try testing.expect(srv.peerChain() == null); // 1b.19 default
}

test "peerChain with retain_chain on + 1-cert chain returns single-entry slice == leaf" {
    // Sanity-check the byte-identity contract when only the leaf is in
    // play (self-signed test cert reused as cert+root). The returned
    // slice MUST have length 1 and the first entry MUST byte-match
    // peerCertificate().
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var srv = NonBlock.initWithAllocator(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
        .client_auth = .{
            .root_ca = root_ca,
            .auth_type = .require,
            .retain_chain = true,
        },
    }, alloc);
    defer srv.deinit();
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth,
    });

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());

    const chain = srv.peerChain();
    try testing.expect(chain != null);
    try testing.expectEqual(@as(usize, 1), chain.?.len);

    const leaf = srv.peerCertificate().?;
    try testing.expectEqualSlices(u8, leaf, chain.?[0]);
    // It's a copy — different pointer from peerCertificate.
    try testing.expect(chain.?[0].ptr != leaf.ptr);
}

test "peerChain with retain_chain on + 2-cert chain returns leaf-first ordering" {
    // The load-bearing multi-cert test. Client presents leaf +
    // intermediate (concatenated in mtls_chain_leaf_cert.pem); server
    // trust-anchors at root. Server's peerChain() MUST return 2
    // entries; chain[0] MUST be the leaf cert (matching peerCertificate),
    // chain[1] MUST be the intermediate.
    //
    // The fixture was generated via openssl per docs/phase-1b.19-*/plan.md
    // Task 3 step 1.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    // Server uses the existing self-signed cert; trust anchor is the
    // chain's root (mtls_chain_root_cert.pem). Client cert is the
    // leaf+intermediate bundle; client's private key signs
    // CertificateVerify.
    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_chain_leaf_pem, mtls_chain_leaf_key_pem);
    defer client_auth.deinit(alloc);
    var server_root = try cert.fromSlice(alloc, io, mtls_chain_root_pem);
    defer server_root.deinit(alloc);
    var client_root = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer client_root.deinit(alloc);

    var srv = NonBlock.initWithAllocator(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
        .client_auth = .{
            .root_ca = server_root,
            .auth_type = .require,
            .max_chain_depth = 4,
            .retain_chain = true,
        },
    }, alloc);
    defer srv.deinit();
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = client_root,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth,
    });

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());

    const chain = srv.peerChain();
    try testing.expect(chain != null);
    try testing.expectEqual(@as(usize, 2), chain.?.len);

    // Extract the expected leaf + intermediate DER from the fixture for
    // byte-identity comparison. `Bundle.map` is a `HashMapUnmanaged`, so
    // iteration order is NOT guaranteed — sort the offsets ascending
    // before parsing. `Bundle.fromSlice` appends DER bytes in PEM order
    // (top-down), so the smaller offset is the leaf and the larger is
    // the intermediate.
    var fixture_bundle = try cert.fromSlice(alloc, io, mtls_chain_leaf_pem);
    defer fixture_bundle.deinit(alloc);
    try testing.expectEqual(@as(u32, 2), fixture_bundle.map.size);
    var offsets: [2]u32 = undefined;
    var n: usize = 0;
    var it = fixture_bundle.map.iterator();
    while (it.next()) |e| : (n += 1) {
        offsets[n] = e.value_ptr.*;
    }
    if (offsets[0] > offsets[1]) std.mem.swap(u32, &offsets[0], &offsets[1]);
    const o0 = try Certificate.der.Element.parse(fixture_bundle.bytes.items, offsets[0]);
    const o1 = try Certificate.der.Element.parse(fixture_bundle.bytes.items, offsets[1]);
    const expected_leaf = fixture_bundle.bytes.items[offsets[0]..o0.slice.end];
    const expected_intm = fixture_bundle.bytes.items[offsets[1]..o1.slice.end];

    // Load-bearing ordering assertion: chain[0] == leaf, chain[1] == intermediate.
    try testing.expectEqualSlices(u8, expected_leaf, chain.?[0]);
    try testing.expectEqualSlices(u8, expected_intm, chain.?[1]);

    // Leaf is also reachable via peerCertificate() (1b.13 contract).
    try testing.expectEqualSlices(u8, expected_leaf, srv.peerCertificate().?);
}

test "peerChain with retain_chain on + .request + no cert returns null" {
    // .request mode invites a cert but tolerates an empty Certificate
    // flight. When the client declines, retain_chain has nothing to
    // capture — peerChain() stays null, same as peerCertificate().
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var srv = NonBlock.initWithAllocator(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
        .client_auth = .{
            .root_ca = root_ca,
            .auth_type = .request,
            .retain_chain = true,
        },
    }, alloc);
    defer srv.deinit();
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
        // No auth — client declines to authenticate.
    });

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());
    try testing.expect(srv.peerCertificate() == null);
    try testing.expect(srv.peerChain() == null);
}

// ---------------------------------------------------------------------
// SNI — sniHost lifetime + awaiting_auth pause + setAuth + rejectNoMatch
// ---------------------------------------------------------------------

test "sniHost survives across awaiting_auth pause" {
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    const expected_sni = "example.test.local";

    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = expected_sni,
        .insecure_skip_verify = true,
        .now = now,
    });
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null, // resolved via setAuth()
        .now = now,
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_len: usize = 0;
    var cs_len: usize = 0;

    // Round 1: client emits ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Round 2: server consumes ClientHello → should pause at .awaiting_auth.
    const sr1 = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());
    try testing.expectEqual(@as(usize, 0), sr1.send.len);

    // sniHost captured. Snapshot the bytes.
    const sni_first = srv.sniHost();
    try testing.expect(sni_first != null);
    try testing.expectEqualStrings(expected_sni, sni_first.?);

    // Idempotent: calling run() again without resolving should still
    // report awaiting_auth (the SNI bytes survive even though the input
    // buffer has been overwritten with zeros from the moveForwards).
    @memset(cs_buf[0..cs_len], 0); // scribble the input buffer
    cs_len = 0;
    const sr2 = try srv.run(&.{}, &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());
    try testing.expectEqual(@as(usize, 0), sr2.send.len);

    // CRITICAL: SNI bytes survive the input-buffer scribble. This is the
    // load-bearing lifetime test — if `sni_host_buf` were a slice into
    // the input buffer, this would now point at zeros.
    const sni_second = srv.sniHost();
    try testing.expect(sni_second != null);
    try testing.expectEqualStrings(expected_sni, sni_second.?);

    // Resolve via setAuth (null new params = preserve Options defaults).
    srv.setAuth(&server_auth, null, null, null);
    try testing.expectEqual(NonBlock.RunState.in_progress, srv.runState());

    var rounds: usize = 0;
    while (!cli.done() or !srv.done()) : (rounds += 1) {
        if (rounds > 12) return error.HandshakeTooManyRounds;
        if (!cli.done()) {
            const cr = try cli.run(sc_buf[0..sc_len], &cs_buf);
            if (cr.recv_pos > 0) {
                const remaining = sc_len - cr.recv_pos;
                if (remaining > 0) std.mem.copyForwards(u8, sc_buf[0..remaining], sc_buf[cr.recv_pos..sc_len]);
                sc_len = remaining;
            }
            cs_len = cr.send.len;
        }
        if (!srv.done()) {
            const sr = try srv.run(cs_buf[0..cs_len], &sc_buf);
            if (sr.recv_pos > 0) {
                const remaining = cs_len - sr.recv_pos;
                if (remaining > 0) std.mem.copyForwards(u8, cs_buf[0..remaining], cs_buf[sr.recv_pos..cs_len]);
                cs_len = remaining;
            }
            sc_len = sr.send.len;
        }
    }
    try testing.expect(cli.done());
    try testing.expect(srv.done());
    // SNI still readable post-handshake.
    try testing.expectEqualStrings(expected_sni, srv.sniHost().?);
}

test "setAuth swaps server cert during handshake" {
    // Two CertKeyPairs — both backed by the same cert/key fixture (we
    // can't easily build two distinct self-signed P-256 chains in a
    // pure-Zig test). The test verifies that the cert passed via
    // setAuth (NOT a hypothetical opt.auth) is the one used; the cipher
    // succeeds end-to-end.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var swap_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer swap_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "localhost",
        .insecure_skip_verify = true,
        .now = now,
    });
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_len: usize = 0;
    var cs_len: usize = 0;

    // Client emits ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());
    cs_len = 0;

    // Resolve (null new params = preserve Options defaults).
    srv.setAuth(&swap_auth, null, null, null);

    // Drive to completion.
    var rounds: usize = 0;
    while (!cli.done() or !srv.done()) : (rounds += 1) {
        if (rounds > 12) return error.HandshakeTooManyRounds;
        if (!cli.done()) {
            const cr = try cli.run(sc_buf[0..sc_len], &cs_buf);
            if (cr.recv_pos > 0) {
                const remaining = sc_len - cr.recv_pos;
                if (remaining > 0) std.mem.copyForwards(u8, sc_buf[0..remaining], sc_buf[cr.recv_pos..sc_len]);
                sc_len = remaining;
            }
            cs_len = cr.send.len;
        }
        if (!srv.done()) {
            const sr = try srv.run(cs_buf[0..cs_len], &sc_buf);
            if (sr.recv_pos > 0) {
                const remaining = cs_len - sr.recv_pos;
                if (remaining > 0) std.mem.copyForwards(u8, cs_buf[0..remaining], cs_buf[sr.recv_pos..cs_len]);
                cs_len = remaining;
            }
            sc_len = sr.send.len;
        }
    }
    try testing.expect(cli.done());
    try testing.expect(srv.done());
    try testing.expect(cli.cipher() != null);
    try testing.expect(srv.cipher() != null);
}

test "RFC 6066 unknown NameType stops list parsing" {
    // Craft a ClientHello manually targeting just readClientHello. We
    // exercise the SNI parse path by setting up a Handshake struct with
    // a fixed Reader pointed at a synthesized ClientHello where the
    // server_name extension starts with a non-host_name NameType.
    //
    // The simpler approach: drive a real client handshake (host = "X")
    // first and capture its bytes, then mutate the captured ClientHello
    // to flip the first NameType. But this is fragile across lib
    // changes. Instead we use a direct unit test below.

    // For now, verify the parse logic via a minimal harness. We need a
    // Handshake instance and an Io.Reader fed a synthesized ClientHello.
    // Building a fully valid ClientHello is non-trivial — instead we
    // test the SNI parse logic at the level of the server's response to
    // a real client: a normal valid handshake should observe SNI when
    // the client sets host = "test.example.com".
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client driving SNI = "test.example.com" — host_name(0) entry.
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "test.example.com",
        .insecure_skip_verify = true,
        .now = now,
    });
    var srv = NonBlock.init(.{
        .rng = rng,
        .auth = &server_auth,
        .now = now,
    });

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;

    // Client emits ClientHello.
    const cr = try cli.run(&sc_buf, &cs_buf);

    // Locate the server_name extension in the emitted ClientHello and
    // flip the NameType byte (offset = first byte of ServerName entry,
    // immediately after the 2-byte server_name_list length).
    // Extension type 0x00 0x00; extension len (u16); server_name_list
    // len (u16); NameType (u8).
    const cs_emitted = cs_buf[0..cr.send_pos];
    var i: usize = 0;
    var found: ?usize = null;
    while (i + 4 <= cs_emitted.len) : (i += 1) {
        if (cs_emitted[i] == 0x00 and cs_emitted[i + 1] == 0x00) {
            // Possibly the server_name extension — verify by computing
            // expected length: ext_len = host_len + 5.
            const ext_len = (@as(u16, cs_emitted[i + 2]) << 8) | cs_emitted[i + 3];
            if (ext_len == "test.example.com".len + 5) {
                // server_name_list at i+4..; first byte at i+6 is NameType.
                if (i + 6 < cs_emitted.len) {
                    found = i + 6;
                    break;
                }
            }
        }
    }
    try testing.expect(found != null);

    // Mutate the NameType from 0 (host_name) → 1 (unknown).
    cs_buf[found.?] = 1;

    // Server consumes the mutated ClientHello. Our parse should STOP at
    // the unknown NameType and treat SNI as absent.
    const sr = try srv.run(cs_buf[0..cr.send_pos], &sc_buf);
    _ = sr;
    try testing.expect(srv.sniHost() == null);
}

test "rejectNoMatch sends unrecognized_name alert" {
    // Setup: client + SNI-dispatch server; server calls rejectNoMatch
    // during the awaiting_auth pause; the next run() should raise
    // TlsUnrecognizedName.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "wont-be-served.example",
        .insecure_skip_verify = true,
        .now = now,
    });
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;

    const cr = try cli.run(&sc_buf, &cs_buf);
    _ = try srv.run(cs_buf[0..cr.send_pos], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    srv.rejectNoMatch();

    // Next run() should bubble out TlsUnrecognizedName from serverFlight.
    try testing.expectError(error.TlsUnrecognizedName, srv.run(&.{}, &sc_buf));
}

// =====================================================================
// Phase 1b.24 — setAuth widened: ?ClientAuth + ?alpn_protocols overrides
// =====================================================================

test "setAuth(cert, null, null) preserves Options defaults (backward-compat)" {
    // Construct an SNI-dispatch server with Options.client_auth set and
    // Options.alpn_protocols set. Call setAuth(cert, null, null). Both
    // null params MUST preserve the values in Options — bit-identical
    // pre-1b.24 behavior. Handshake must complete successfully and the
    // negotiated ALPN must match what Options specified.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client advertises ALPN "http/1.1".
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "test.local",
        .insecure_skip_verify = true,
        .now = now,
        .alpn_protocols = &.{"http/1.1"},
    });
    // Server has Options.alpn_protocols = ["http/1.1"] at construction.
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
        .alpn_protocols = &.{"http/1.1"},
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // Client emits ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses at awaiting_auth.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // Resolve — null for both new params: preserves Options defaults.
    srv.setAuth(&server_auth, null, null, null);
    try testing.expectEqual(NonBlock.RunState.in_progress, srv.runState());

    // Drive to completion.
    try driveHandshake(&cli, &srv, 12);
    try testing.expect(cli.done());
    try testing.expect(srv.done());

    // Options.alpn_protocols = ["http/1.1"] was preserved — negotiated ALPN
    // should be "http/1.1".
    try testing.expectEqualStrings("http/1.1", srv.alpnProtocol().?);
    try testing.expectEqualStrings("http/1.1", cli.alpnProtocol().?);
}

test "setAuth(cert, null, alpn_override) selects ALPN from per-host override list" {
    // Listener Options.alpn_protocols = ["h2","http/1.1"] (full list).
    // Client offers ["h2","http/1.1"].
    // setAuth resolves with alpn_override = ["http/1.1"] only.
    // Expected: negotiated ALPN is "http/1.1" — the per-host restriction took effect.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client advertises both "h2" and "http/1.1".
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "api.test.local",
        .insecure_skip_verify = true,
        .now = now,
        .alpn_protocols = &.{ "h2", "http/1.1" },
    });
    // Listener supports both.
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
        .alpn_protocols = &.{ "h2", "http/1.1" },
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // Override: this host only supports "http/1.1".
    srv.setAuth(&server_auth, null, &.{"http/1.1"}, null);

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());

    // Override restricted selection to "http/1.1" even though both sides
    // would have negotiated "h2" with the listener-wide list.
    try testing.expectEqualStrings("http/1.1", srv.alpnProtocol().?);
    try testing.expectEqualStrings("http/1.1", cli.alpnProtocol().?);
}

test "setAuth(cert, ClientAuth{...}, null) causes server to emit CertificateRequest" {
    // Listener Options.client_auth = null (no mTLS by default).
    // setAuth is called with a per-host ClientAuth override.
    // Expected: handshake completes with mTLS — server gets the client cert.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client sends a cert.
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "secure.test.local",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth,
    });
    // Listener has NO client_auth configured.
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
        .client_auth = null,
    }, alloc);
    defer srv.deinit();

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // Override: this host requires client cert authentication.
    srv.setAuth(&server_auth, .{
        .root_ca = root_ca,
        .auth_type = .require,
    }, null, null);

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());

    // peerCertificate should be populated — the per-host client_auth override
    // caused CertificateRequest to be emitted, and the client responded.
    try testing.expect(srv.peerCertificate() != null);
    try testing.expect(srv.peerCertificate().?.len > 0);
}

test "setAuth with non-overlapping ALPN override emits no_application_protocol error" {
    // Listener Options.alpn_protocols = ["http/1.1"].
    // Client offers ["http/1.1"].
    // setAuth is called with alpn_override = ["h2"] — no overlap with client.
    // Expected: run() returns error.TlsNoApplicationProtocol.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client advertises only "http/1.1".
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "old.test.local",
        .insecure_skip_verify = true,
        .now = now,
        .alpn_protocols = &.{"http/1.1"},
    });
    // Listener supports "http/1.1".
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
        .alpn_protocols = &.{"http/1.1"},
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses at awaiting_auth.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // Override: this host only accepts "h2" — but the client didn't offer it.
    srv.setAuth(&server_auth, null, &.{"h2"}, null);

    // The next run() should fail with TlsNoApplicationProtocol because the
    // per-host override has no overlap with the client's offer.
    var sc_buf2: [max_ciphertext_record_len]u8 = undefined;
    try testing.expectError(error.TlsNoApplicationProtocol, srv.run(&.{}, &sc_buf2));
}

test "setAuth is idempotent — second call restamps cert, preserves first resolved state" {
    // Drive the handshake to awaiting_auth, call setAuth twice. The second
    // call must not corrupt state. Handshake should complete successfully.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "test.local",
        .insecure_skip_verify = true,
        .now = now,
    });
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // First call — resolves auth.
    srv.setAuth(&server_auth, null, null, null);
    try testing.expectEqual(NonBlock.RunState.in_progress, srv.runState());

    // Second call — must be a no-op / restamp; must NOT panic or corrupt state.
    srv.setAuth(&server_auth, null, null, null);
    // State must still be in_progress (not re-paused or corrupted).
    try testing.expectEqual(NonBlock.RunState.in_progress, srv.runState());

    // Drive to completion.
    try driveHandshake(&cli, &srv, 12);
    try testing.expect(cli.done());
    try testing.expect(srv.done());
}

test "readClientHello rejects oversized client ALPN list with TlsDecodeError" {
    // Construct a synthetic ClientHello whose ALPN extension carries a
    // protocol list whose declared length exceeds the 512-byte buffer cap.
    // The handshake MUST fail with error.TlsDecodeError, not silently
    // truncate (which would allow a malicious client to push real protocol
    // matches into the truncated tail of an oversized list).
    //
    // Strategy: drive a real client handshake to capture a valid ClientHello
    // byte-for-byte, then find the ALPN extension and replace its list_len
    // field with a value > 512. Feed the mutated bytes to a fresh server.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client advertises a short ALPN list (will be mutated below).
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "test.local",
        .insecure_skip_verify = true,
        .now = now,
        .alpn_protocols = &.{"http/1.1"},
    });
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
        .alpn_protocols = &.{"http/1.1"},
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;

    // Client emits ClientHello into cs_buf.
    const cr = try cli.run(&sc_buf, &cs_buf);
    const cs_emitted = cs_buf[0..cr.send_pos];

    // Locate the ALPN extension (type 0x00 0x10) in the ClientHello.
    // Layout after extension type+len (4 bytes): u16 alpn_list_len, then
    // u8 proto_len + proto_bytes per entry.
    // We need to find the ALPN list_len u16 field and replace it with
    // a value > 512 (e.g. 0x0201 = 513).
    var found_alpn_list_len_pos: ?usize = null;
    {
        var i: usize = 0;
        while (i + 6 <= cs_emitted.len) : (i += 1) {
            // ALPN extension type = 0x00 0x10
            if (cs_emitted[i] == 0x00 and cs_emitted[i + 1] == 0x10) {
                // i+2, i+3 = extension data length
                // i+4, i+5 = ALPN protocol list length (this is what we mutate)
                found_alpn_list_len_pos = i + 4;
                break;
            }
        }
    }
    try testing.expect(found_alpn_list_len_pos != null);
    const pos = found_alpn_list_len_pos.?;

    // Overwrite the ALPN list_len with 513 (> 512 buffer cap).
    // Big-endian u16: 0x02 0x01 = 513.
    cs_buf[pos] = 0x02;
    cs_buf[pos + 1] = 0x01;

    // Server MUST reject the oversized list with TlsDecodeError.
    try testing.expectError(error.TlsDecodeError, srv.run(cs_emitted, &sc_buf));
}

test "setAuth applies cert + client_auth + alpn atomically before next run()" {
    // Listener Options.alpn_protocols = ["http/1.1"], client_auth = null.
    // Client offers ["h2","http/1.1"] and sends a client cert.
    // setAuth(cert, ClientAuth{.require}, &.{"h2"}) must atomically:
    //   (a) pick "h2" from the client's ALPN offer, AND
    //   (b) emit CertificateRequest (per-host mTLS override).
    // Both must happen in the SAME server flight.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth_ckp = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth_ckp.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client offers both ALPN protocols and sends a cert.
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "both.test.local",
        .insecure_skip_verify = true,
        .now = now,
        .alpn_protocols = &.{ "h2", "http/1.1" },
        .auth = &client_auth_ckp,
    });
    // Listener: http/1.1 only ALPN, no mTLS.
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
        .alpn_protocols = &.{"http/1.1"},
        .client_auth = null,
    }, alloc);
    defer srv.deinit();

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // Atomic override: BOTH per-host client_auth AND per-host ALPN applied in one call.
    srv.setAuth(&server_auth, .{
        .root_ca = root_ca,
        .auth_type = .require,
    }, &.{"h2"}, null);

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());

    // (a) ALPN override took effect: "h2" selected, not "http/1.1".
    try testing.expectEqualStrings("h2", srv.alpnProtocol().?);
    try testing.expectEqualStrings("h2", cli.alpnProtocol().?);

    // (b) mTLS override took effect: client cert captured.
    try testing.expect(srv.peerCertificate() != null);
    try testing.expect(srv.peerCertificate().?.len > 0);
}

// ---------------------------------------------------------------------
// Phase 1b.25 — certificate_authorities extension emission
// ---------------------------------------------------------------------

test "Phase 1b.25 — makeCertificateRequest with cert_authorities_ext_bytes=null emits no extension" {
    // F2: null bypass — default ClientAuth must NOT emit extension_type=47.
    var buf: [4096]u8 = undefined;
    var w: record.Writer = .init(&buf);

    try Handshake.makeCertificateRequest(&w, null);

    // Walk the emitted CR record's extensions block; assert no
    // extension_type=47 (0x002F = certificate_authorities) entry.
    const out = w.buffered();
    try testing.expect(out.len > 7);
    // Layout: handshake header (4) + ctx_len (1) + ext_list_len (2) = 7 bytes preamble.
    var idx: usize = 4 + 1 + 2;
    while (idx + 4 <= out.len) {
        const ext_type = std.mem.readInt(u16, out[idx..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, out[idx + 2 ..][0..2], .big);
        try testing.expect(ext_type != 0x002F);
        idx += 4 + ext_data_len;
    }
}

test "Phase 1b.25 — makeCertificateRequest with cert_authorities_ext_bytes=<5 bytes> emits extension 47" {
    // F1: happy path — hand-crafted payload must appear verbatim under extension_type=47.
    var buf: [4096]u8 = undefined;
    var w: record.Writer = .init(&buf);

    // Hand-crafted payload: 1 DN entry, 1 byte of content.
    // Wire: <u16 authorities_length=3><u16 dn_len=1><0xAB>
    const payload = [_]u8{ 0x00, 0x03, 0x00, 0x01, 0xAB };

    try Handshake.makeCertificateRequest(&w, payload[0..]);

    const out = w.buffered();

    // Walk extensions to find extension_type=47.
    var idx: usize = 4 + 1 + 2;
    var found = false;
    while (idx + 4 <= out.len) {
        const ext_type = std.mem.readInt(u16, out[idx..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, out[idx + 2 ..][0..2], .big);
        if (ext_type == 0x002F) {
            found = true;
            try testing.expectEqual(@as(u16, payload.len), ext_data_len);
            try testing.expectEqualSlices(u8, payload[0..], out[idx + 4 .. idx + 4 + payload.len]);
            break;
        }
        idx += 4 + ext_data_len;
    }
    try testing.expect(found);
}

test "Phase 1b.25 — makeCertificateRequest with 65000-byte payload round-trips" {
    // F3: large payload — must not truncate or overflow.
    var buf: [80 * 1024]u8 = undefined;
    var w: record.Writer = .init(&buf);

    var payload_buf: [65000]u8 = undefined;
    @memset(&payload_buf, 0x5A);
    // Patch the first two bytes to a nominally valid authorities_length:
    // 65000 - 2 = 64998 bytes of "content". Content isn't valid DN entries;
    // the library is opaque to the payload, so this is fine for a round-trip test.
    std.mem.writeInt(u16, payload_buf[0..2], 64998, .big);

    try Handshake.makeCertificateRequest(&w, payload_buf[0..]);

    const out = w.buffered();
    var idx: usize = 4 + 1 + 2;
    var found = false;
    while (idx + 4 <= out.len) {
        const ext_type = std.mem.readInt(u16, out[idx..][0..2], .big);
        const ext_data_len = std.mem.readInt(u16, out[idx + 2 ..][0..2], .big);
        if (ext_type == 0x002F) {
            found = true;
            try testing.expectEqual(@as(u16, 65000), ext_data_len);
            try testing.expectEqualSlices(u8, payload_buf[0..], out[idx + 4 .. idx + 4 + 65000]);
            break;
        }
        idx += 4 + ext_data_len;
    }
    try testing.expect(found);
}

test "Phase 1b.25 — setAuth with cert_authorities_ext_bytes threads through to CertificateRequest" {
    // F4: SNI dispatch parity — setAuth-provided cert_authorities_ext_bytes must
    // reach the wire. We drive a full handshake via driveHandshake() using the
    // same per-host setAuth override path as the existing 1b.24 dispatch test.
    // Successful handshake completion (peerCertificate populated) confirms that:
    //   (a) setAuth correctly stamped cert_authorities_ext_bytes into opt.client_auth,
    //   (b) serverFlight threaded ca.cert_authorities_ext_bytes into makeCertificateRequest,
    //   (c) the extension was emitted and the RFC-compliant client processed it without error.
    // Byte-level emission is verified by F1; this test closes the integration loop.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var client_auth_ckp = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer client_auth_ckp.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Hand-crafted 5-byte cert_authorities payload (same as F1).
    const payload = [_]u8{ 0x00, 0x03, 0x00, 0x01, 0xAB };

    // Client sends a cert (mTLS).
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "ca-ext.test.local",
        .insecure_skip_verify = true,
        .now = now,
        .auth = &client_auth_ckp,
    });
    // Listener has NO client_auth configured — will be overridden via setAuth.
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
        .client_auth = null,
    }, alloc);
    defer srv.deinit();

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // ClientHello.
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses at awaiting_auth.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // Override: per-host client_auth WITH cert_authorities_ext_bytes set.
    // This stamps the field into opt.client_auth, which serverFlight then
    // threads into makeCertificateRequest.
    srv.setAuth(&server_auth, .{
        .root_ca = root_ca,
        .auth_type = .require,
        .cert_authorities_ext_bytes = payload[0..],
    }, null, null);

    try driveHandshake(&cli, &srv, 12);
    try testing.expect(srv.done());

    // Client cert captured — the CertificateRequest (with the extension) was
    // processed successfully and the client responded with its certificate.
    try testing.expect(srv.peerCertificate() != null);
    try testing.expect(srv.peerCertificate().?.len > 0);
}

// =====================================================================
// Phase OCSP-wire — setAuth 4th param + serverFlight gate
// =====================================================================

test "OCSP-wire — setAuth stores ocsp_staple; serverFlight gates on client_requested_ocsp" {
    // Construct an SNI-dispatch server. Drive client to emit ClientHello
    // (no status_request) so the server reaches awaiting_auth. Then:
    //   (a) call setAuth with a non-null ocsp_staple — verify it lands in
    //       inner.ocsp_staple.
    //   (b) verify client_requested_ocsp is false (no status_request in
    //       ClientHello) — the gate that serverFlight uses.
    //   (c) complete the handshake successfully (staple ignored because
    //       client did not ask; wire is bit-identical legacy).
    // This pins the "4th param lands in inner.ocsp_staple" invariant and
    // validates the gate without requiring a live OCSP fetch.
    const alloc = testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var server_auth = try common.CertKeyPair.fromSlice(alloc, io, mtls_test_cert_pem, mtls_test_key_pem);
    defer server_auth.deinit(alloc);
    var root_ca = try cert.fromSlice(alloc, io, mtls_test_cert_pem);
    defer root_ca.deinit(alloc);

    // Client does NOT set request_ocsp — status_request extension is absent.
    var cli = handshake_client_mod.NonBlock.init(.{
        .rng = rng,
        .root_ca = root_ca,
        .host = "test.local",
        .insecure_skip_verify = true,
        .now = now,
    });
    var srv = NonBlock.initForSniDispatch(.{
        .rng = rng,
        .auth = null,
        .now = now,
    }, null);

    var cs_buf: [max_ciphertext_record_len]u8 = undefined;
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    var cs_len: usize = 0;

    // Client emits ClientHello (no status_request).
    const cr1 = try cli.run(&sc_buf, &cs_buf);
    cs_len = cr1.send.len;

    // Server pauses at awaiting_auth.
    _ = try srv.run(cs_buf[0..cs_len], &sc_buf);
    try testing.expectEqual(NonBlock.RunState.awaiting_auth, srv.runState());

    // (b) client did not send status_request → flag must be false.
    try testing.expect(!srv.clientRequestedOcsp());
    // Also check the raw field directly (same-file access).
    try testing.expect(!srv.inner.client_requested_ocsp);

    // (a) Supply staple via the new 4th param.
    const staple: []const u8 = "OCSP-STAPLE-BYTES";
    srv.setAuth(&server_auth, null, null, staple);
    try testing.expectEqual(NonBlock.RunState.in_progress, srv.runState());

    // Verify the staple landed in inner.ocsp_staple.
    try testing.expect(srv.inner.ocsp_staple != null);
    try testing.expectEqualStrings(staple, srv.inner.ocsp_staple.?);

    // (c) Drive to completion — staple not emitted (client didn't ask),
    //     but the handshake must still succeed bit-identically.
    try driveHandshake(&cli, &srv, 12);
    try testing.expect(cli.done());
    try testing.expect(srv.done());
}
