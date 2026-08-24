import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Data classes
// ══════════════════════════════════════════════════════════════════════════════

/// PreKey Bundle published by a Kamui node.
///
/// Contains two keypair surfaces per Signal X3DH spec:
/// - **Ed25519** identity key (`ikPubEd`) — used only for signing; never for DH.
/// - **X25519** identity DH key (`ikPubDh`) — used for DH operations only.
///
/// The separation avoids the birational-map Ed25519→X25519 conversion risk.
/// Both are generated and stored independently.
class PreKeyBundle {
  /// Ed25519 identity public key (32 bytes) — signing surface only.
  final List<int> ikPubEd;

  /// X25519 identity DH public key (32 bytes) — DH surface only.
  final List<int> ikPubDh;

  /// X25519 Signed PreKey public (32 bytes).
  final List<int> spkPub;

  /// Ed25519 signature of [spkPub] produced by [ikPubEd]'s private key (64 bytes).
  /// Prevents MITM key substitution attacks.
  final List<int> spkSig;

  /// Explicit One-Time PreKey identifier.
  final int? opkId;

  /// X25519 One-Time PreKey (32 bytes). Optional — omitted when pool is exhausted.
  final List<int>? opkPub;

  const PreKeyBundle({
    required this.ikPubEd,
    required this.ikPubDh,
    required this.spkPub,
    required this.spkSig,
    this.opkId,
    this.opkPub,
  });

  Map<String, dynamic> toJson() => {
    'ik_ed':   base64Encode(ikPubEd),
    'ik_dh':   base64Encode(ikPubDh),
    'spk':     base64Encode(spkPub),
    'spk_sig': base64Encode(spkSig),
    if (opkId != null) 'opk_id': opkId,
    if (opkPub != null) 'opk': base64Encode(opkPub!),
  };

  factory PreKeyBundle.fromJson(Map<String, dynamic> json) {
    return PreKeyBundle(
      ikPubEd: base64Decode(json['ik_ed']   as String),
      ikPubDh: base64Decode(json['ik_dh']   as String),
      spkPub:  base64Decode(json['spk']     as String),
      spkSig:  base64Decode(json['spk_sig'] as String),
      opkId:   json['opk_id'] as int?,
      opkPub:  json['opk'] != null
               ? base64Decode(json['opk'] as String)
               : null,
    );
  }
}

/// Result of a successful X3DH initiator handshake.
class X3dhResult {
  /// 32-byte shared secret (SK) derived via HKDF-SHA256.
  final Uint8List sharedSecret;

  /// Alice's ephemeral X25519 public key — MUST be sent to Bob in the wire header.
  final List<int> ekPub;

  /// The OPK ID used in DH4 if OPK was present in the bundle.
  final int? opkId;

  const X3dhResult({
    required this.sharedSecret,
    required this.ekPub,
    this.opkId,
  });
}

/// Envelope transmitted on the wire for the initial message of a v4 conversation.
///
/// Contains Alice's public parameters (Ed25519 identity key, X25519 DH identity key,
/// Ed25519 identity-binding signature over IK_ed ‖ IK_dh, ephemeral public key,
/// and consumed OPK identifier) along with the first Double-Ratchet-encrypted payload.
/// This gives Bob all information required to cryptographically verify Alice's identity,
/// compute the X3DH shared secret, and initialize his receiver ratchet state.
class HandshakeInitEnvelope {
  static const String envelopeType = 'kamui_v4_handshake_init';

  /// Alice's Ed25519 identity public key (32 bytes).
  final List<int> ikEd;

  /// Alice's X25519 DH identity public key (32 bytes).
  final List<int> ikDh;

  /// Alice's cryptographic identity-binding signature (64 bytes):
  /// Ed25519.sign(IK_ed_priv, "Kamui-X3DH-Identity-Binding-v1" ‖ IK_ed_pub ‖ IK_dh_pub)
  final List<int> ikSig;

  /// Alice's ephemeral X25519 public key (32 bytes).
  final List<int> ek;

  /// The OPK ID used in DH4 if OPK was present in Bob's bundle.
  final int? opkIdUsed;

  /// The first Double-Ratchet-encrypted message payload (`"kamui_v4:<header>:<nonce>:<ct>"`).
  final String firstMessage;

  const HandshakeInitEnvelope({
    required this.ikEd,
    required this.ikDh,
    required this.ikSig,
    required this.ek,
    this.opkIdUsed,
    required this.firstMessage,
  });

  Map<String, dynamic> toJson() => {
    'type': envelopeType,
    'ik_ed': base64Encode(ikEd),
    'ik_dh': base64Encode(ikDh),
    'ik_sig': base64Encode(ikSig),
    'ek': base64Encode(ek),
    if (opkIdUsed != null) 'opk_id_used': opkIdUsed,
    'first_message': firstMessage,
  };

  factory HandshakeInitEnvelope.fromJson(Map<String, dynamic> json) {
    if (json['type'] != envelopeType) {
      throw FormatException('Invalid HandshakeInitEnvelope type: ${json['type']}');
    }
    return HandshakeInitEnvelope(
      ikEd: base64Decode(json['ik_ed'] as String),
      ikDh: base64Decode(json['ik_dh'] as String),
      ikSig: base64Decode(json['ik_sig'] as String),
      ek: base64Decode(json['ek'] as String),
      opkIdUsed: json['opk_id_used'] as int?,
      firstMessage: json['first_message'] as String,
    );
  }

  /// Helper to check if a wire payload is a HandshakeInitEnvelope.
  static bool isHandshakeEnvelope(String payload) {
    final trimmed = payload.trim();
    if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return false;
    try {
      final decoded = jsonDecode(trimmed);
      return decoded is Map<String, dynamic> && decoded['type'] == envelopeType;
    } catch (_) {
      return false;
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// X3DH Service
// ══════════════════════════════════════════════════════════════════════════════

/// Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol
/// as described in the Signal X3DH specification, adapted for Kamui's peer-to-peer
/// I2P context (no central prekey server — bundles exchanged via QR payload).
///
/// ## DH Operations (Initiator / Alice perspective)
/// ```
/// DH1 = X25519(IK_A_dh_priv,  SPK_B_pub)   ← mutual authentication
/// DH2 = X25519(EK_A_priv,     IK_B_dh_pub)  ← initiator forward secrecy
/// DH3 = X25519(EK_A_priv,     SPK_B_pub)    ← responder forward secrecy
/// DH4 = X25519(EK_A_priv,     OPK_B_pub)    ← one-time FS [optional]
///
/// SK = HKDF-SHA256(salt=0x00×32, IKM=DH1‖DH2‖DH3[‖DH4], info="Kamui-X3DH-v3")
/// ```
class X3dhService {
  static const _hkdfInfo = 'Kamui-X3DH-v3';
  static const _identityBindingDomain = 'Kamui-X3DH-Identity-Binding-v1';
  static final _ed25519  = Ed25519();
  static final _x25519   = X25519();

  // ── Public API ─────────────────────────────────────────────────────────────

  /// Computes the canonical domain-separated transcript for identity binding.
  static List<int> computeIdentityBindingTranscript(List<int> ikEd, List<int> ikDh) {
    return [
      ...utf8.encode(_identityBindingDomain),
      ...ikEd,
      ...ikDh,
    ];
  }

  /// Verifies that [ikSig] is a valid Ed25519 signature over
  /// `("Kamui-X3DH-Identity-Binding-v1" ‖ ikEd ‖ ikDh)` produced by [ikEd].
  static Future<bool> verifyIdentityBinding({
    required List<int> ikEd,
    required List<int> ikDh,
    required List<int> ikSig,
  }) async {
    try {
      if (ikEd.length != 32 || ikDh.length != 32 || ikSig.length != 64) {
        return false;
      }
      final ikPub = SimplePublicKey(ikEd, type: KeyPairType.ed25519);
      final sig   = Signature(ikSig, publicKey: ikPub);
      final transcript = computeIdentityBindingTranscript(ikEd, ikDh);
      return await _ed25519.verify(transcript, signature: sig);
    } catch (_) {
      return false;
    }
  }

  /// Verifies the SPK signature embedded in [bundle].
  ///
  /// Returns `true` only when Ed25519.verify(spkPub, sig=spkSig, key=ikPubEd) passes.
  /// **Callers MUST abort the handshake if this returns `false`.**
  static Future<bool> verifyPreKeyBundle(PreKeyBundle bundle) async {
    try {
      final ikPub = SimplePublicKey(bundle.ikPubEd, type: KeyPairType.ed25519);
      final sig   = Signature(bundle.spkSig, publicKey: ikPub);
      return await _ed25519.verify(bundle.spkPub, signature: sig);
    } catch (_) {
      return false;
    }
  }

  /// **Alice (Initiator)** performs the X3DH handshake against Bob's [bundleB].
  ///
  /// 1. Verify [bundleB].spkSig — throws [X3dhException] on failure (Fail-Closed).
  /// 2. Validate OPK consistency (Four explicit states).
  /// 3. Generate ephemeral key EK_A.
  /// 4. Compute DH1–DH3 (+ optional DH4 if OPK present).
  /// 5. Derive 32-byte SK via HKDF-SHA256.
  static Future<X3dhResult> initiatorHandshake({
    required SimpleKeyPair ikADh,    // Alice's X25519 DH identity key
    required PreKeyBundle  bundleB,  // Bob's PreKeyBundle
  }) async {
    // 1. Verify SPK signature — abort on MITM
    if (!await verifyPreKeyBundle(bundleB)) {
      throw const X3dhException(
        'SPK signature verification failed — possible MITM. Handshake aborted.',
      );
    }

    // 2. Validate OPK consistency (Four explicit states — Fail-Closed)
    if (bundleB.opkPub != null && bundleB.opkId == null) {
      throw const X3dhException(
        'Malformed PreKeyBundle: opkPub present without explicit opkId',
      );
    }
    if (bundleB.opkPub == null && bundleB.opkId != null) {
      throw const X3dhException(
        'Malformed PreKeyBundle: opkId present without opkPub',
      );
    }

    // 3. Generate fresh ephemeral key EK_A
    final ekA    = await _x25519.newKeyPair();
    final ekAPub = await ekA.extractPublicKey();

    // 4. Reconstruct Bob's DH public keys
    final ikBDhPub = SimplePublicKey(bundleB.ikPubDh, type: KeyPairType.x25519);
    final spkBPub  = SimplePublicKey(bundleB.spkPub,  type: KeyPairType.x25519);

    // 5. DH operations
    // DH1 = X25519(IK_A_dh_priv, SPK_B_pub) — mutual authentication
    final dh1 = await _dh(ikADh, spkBPub);
    // DH2 = X25519(EK_A_priv, IK_B_dh_pub) — initiator forward secrecy
    final dh2 = await _dh(ekA,   ikBDhPub);
    // DH3 = X25519(EK_A_priv, SPK_B_pub) — responder forward secrecy
    final dh3 = await _dh(ekA,   spkBPub);

    // DH4 = X25519(EK_A_priv, OPK_B_pub) — one-time FS [optional]
    List<int>? dh4;
    int? usedOpkId;
    if (bundleB.opkPub != null && bundleB.opkId != null) {
      final opkBPub = SimplePublicKey(bundleB.opkPub!, type: KeyPairType.x25519);
      dh4 = await _dh(ekA, opkBPub);
      usedOpkId = bundleB.opkId;
    }

    // 6. Derive shared secret
    final sk = await _hkdf([...dh1, ...dh2, ...dh3, ...?dh4]);

    return X3dhResult(
      sharedSecret: sk,
      ekPub:        ekAPub.bytes,
      opkId:        usedOpkId,
    );
  }

  /// **Bob (Responder)** mirrors Alice's DH operations to derive the identical SK.
  ///
  /// [ekAPub] and [ikADhPub] must be extracted from Alice's wire message header.
  static Future<Uint8List> responderHandshake({
    required SimpleKeyPair ikBDh,    // Bob's X25519 DH identity key
    required SimpleKeyPair spkB,     // Bob's X25519 Signed PreKey
    required SimpleKeyPair? opkB,    // Bob's One-Time PreKey (null if not used)
    required List<int>     ekAPub,   // Alice's ephemeral public key (from wire)
    required List<int>     ikADhPub, // Alice's X25519 DH identity public key
  }) async {
    final ikAPubKey = SimplePublicKey(ikADhPub, type: KeyPairType.x25519);
    final ekAKey    = SimplePublicKey(ekAPub,   type: KeyPairType.x25519);

    // DH1 = X25519(SPK_B_priv, IK_A_dh_pub) — symmetric to Alice's DH1
    final dh1 = await _dh(spkB,  ikAPubKey);
    // DH2 = X25519(IK_B_dh_priv, EK_A_pub) — symmetric to Alice's DH2
    final dh2 = await _dh(ikBDh, ekAKey);
    // DH3 = X25519(SPK_B_priv, EK_A_pub) — symmetric to Alice's DH3
    final dh3 = await _dh(spkB,  ekAKey);

    List<int>? dh4;
    if (opkB != null) {
      // DH4 = X25519(OPK_B_priv, EK_A_pub) — symmetric to Alice's DH4
      dh4 = await _dh(opkB, ekAKey);
    }

    return _hkdf([...dh1, ...dh2, ...dh3, ...?dh4]);
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  static Future<List<int>> _dh(
    SimpleKeyPair     localKp,
    SimplePublicKey   remotePub,
  ) async {
    final secret = await _x25519.sharedSecretKey(
      keyPair:         localKp,
      remotePublicKey: remotePub,
    );
    return secret.extractBytes();
  }

  /// HKDF-SHA256 (RFC 5869) with 32-byte zero salt and Kamui domain info label.
  ///
  ///   PRK = HMAC-SHA256(salt=0x00×32, IKM)
  ///   OKM = HMAC-SHA256(PRK, info‖0x01)   [single expand block → 32 bytes]
  static Future<Uint8List> _hkdf(List<int> ikm) async {
    final hmac = Hmac.sha256();

    // Extract — PRK
    final salt   = Uint8List(32); // 32 zero bytes per Signal spec
    final prkMac = await hmac.calculateMac(ikm, secretKey: SecretKey(salt));
    final prk    = prkMac.bytes;

    // Expand — T(1), single block sufficient for 32-byte output
    final expandInput = [...utf8.encode(_hkdfInfo), 0x01];
    final okmMac      = await hmac.calculateMac(expandInput, secretKey: SecretKey(prk));

    return Uint8List.fromList(okmMac.bytes); // 32 bytes (SHA-256 output)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Exception
// ══════════════════════════════════════════════════════════════════════════════

/// Thrown when an X3DH handshake cannot be completed securely.
/// Callers MUST propagate this exception and abort the session — no silent downgrade.
class X3dhException implements Exception {
  final String reason;
  const X3dhException(this.reason);

  @override
  String toString() => 'X3dhException: $reason';
}
