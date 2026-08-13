import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════════════════════

/// Maximum number of skipped message keys stored per DH epoch.
/// Prevents unbounded memory growth from adversarial gap attacks.
const int kMaxSkip = 1000;

/// TTL for skipped message keys (milliseconds). Keys older than this are pruned.
/// 30 minutes covers transient network reordering without leaking long-term state.
const int kSkippedKeyTtlMs = 30 * 60 * 1000;

// ══════════════════════════════════════════════════════════════════════════════
// HKDF primitives (shared across ratchet operations)
// ══════════════════════════════════════════════════════════════════════════════

/// Derives two 32-byte keys [rootKey, chainKey] from [rootKey] and [dhOutput]
/// using HKDF-SHA256 with info label `"Kamui-DR-RootKDF-v3"`.
///
/// Used exclusively for the **DH Ratchet Step**:
/// ```
/// (RK', CK) = KDF_RK(RK, DH(DHr, DHs))
/// ```
Future<(Uint8List newRk, Uint8List newCk)> kdfRk(
  Uint8List rootKey,
  List<int>  dhOutput,
) async {
  final hmac = Hmac.sha256();
  // Extract — PRK = HMAC(salt=RK, IKM=dhOutput)
  final prkMac = await hmac.calculateMac(dhOutput, secretKey: SecretKey(rootKey));
  final prk    = prkMac.bytes;
  // Expand — two 32-byte blocks with counter suffix
  final info    = utf8.encode('Kamui-DR-RootKDF-v3');
  final t1Mac   = await hmac.calculateMac([...info, 0x01], secretKey: SecretKey(prk));
  final t2Mac   = await hmac.calculateMac([...t1Mac.bytes, ...info, 0x02], secretKey: SecretKey(prk));
  return (Uint8List.fromList(t1Mac.bytes), Uint8List.fromList(t2Mac.bytes));
}

/// Derives [messageKey, nextChainKey] from the current [chainKey]
/// using HKDF-SHA256 with info label `"Kamui-DR-ChainKDF-v3"`.
///
/// Used for the **Symmetric-Key Ratchet**:
/// ```
/// (CK', MK) = KDF_CK(CK)
/// ```
Future<(Uint8List nextCk, Uint8List mk)> kdfCk(Uint8List chainKey) async {
  final hmac = Hmac.sha256();
  final info  = utf8.encode('Kamui-DR-ChainKDF-v3');
  // PRK = HMAC(salt=CK, IKM=info)
  final prkMac  = await hmac.calculateMac(info, secretKey: SecretKey(chainKey));
  final prk     = prkMac.bytes;
  // T1 → message key, T2 → next chain key
  final mkMac   = await hmac.calculateMac([...info, 0x01], secretKey: SecretKey(prk));
  final nextMac = await hmac.calculateMac([...mkMac.bytes, ...info, 0x02], secretKey: SecretKey(prk));
  return (Uint8List.fromList(nextMac.bytes), Uint8List.fromList(mkMac.bytes));
}

// ══════════════════════════════════════════════════════════════════════════════
// Skipped Message Key Store
// ══════════════════════════════════════════════════════════════════════════════

/// Lookup key for the skipped-message-key table.
/// Identifies a message key by its (sender DH ratchet public key, message index).
class SkippedKeyIndex {
  final List<int> dhPub; // sender's X25519 ratchet pub at that epoch (32 bytes)
  final int       msgN;  // message counter within that epoch

  const SkippedKeyIndex(this.dhPub, this.msgN);

  @override
  bool operator ==(Object other) =>
      other is SkippedKeyIndex &&
      msgN == other.msgN &&
      _listEqual(dhPub, other.dhPub);

  @override
  int get hashCode => Object.hash(msgN, Object.hashAll(dhPub));

  static bool _listEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// Stored entry: the actual message key + its creation timestamp (for TTL pruning).
class _SkippedEntry {
  final Uint8List key;
  final int createdMs;
  _SkippedEntry(this.key, this.createdMs);
}

/// Bounded, TTL-aware store for out-of-order message keys.
///
/// ## Threat model
/// - Gap limit: max [kMaxSkip] skipped keys per DH epoch prevents DoS via
///   adversarially large gaps.
/// - TTL: keys older than [kSkippedKeyTtlMs] are pruned on every insert.
///   This bounds the window in which an attacker can replay old ciphertexts.
class SkippedKeyStore {
  final Map<SkippedKeyIndex, _SkippedEntry> _store = {};

  /// Stores [key] at ([dhPub], [msgN]). Returns `false` if the gap would
  /// exceed [kMaxSkip] (caller should abort the ratchet step).
  bool put(List<int> dhPub, int msgN, Uint8List key) {
    _pruneExpired();
    if (_store.length >= kMaxSkip) return false;
    _store[SkippedKeyIndex(dhPub, msgN)] = _SkippedEntry(key, _nowMs());
    return true;
  }

  /// Retrieves and removes the key for ([dhPub], [msgN]).
  /// Returns `null` if not present (message is not out-of-order or key expired).
  Uint8List? take(List<int> dhPub, int msgN) {
    _pruneExpired();
    final entry = _store.remove(SkippedKeyIndex(dhPub, msgN));
    return entry?.key;
  }

  /// Returns the number of currently stored skipped keys.
  int get length => _store.length;

  void _pruneExpired() {
    final cutoff = _nowMs() - kSkippedKeyTtlMs;
    _store.removeWhere((_, v) => v.createdMs < cutoff);
  }

  static int _nowMs() => DateTime.now().millisecondsSinceEpoch;
}

// ══════════════════════════════════════════════════════════════════════════════
// Double Ratchet Message Header
// ══════════════════════════════════════════════════════════════════════════════

/// Wire header embedded in every Kamui v4 ciphertext.
///
/// ```
/// header = {
///   "dh":  base64(sender_ratchet_pub),   // 32 bytes — triggers DH ratchet if new
///   "n":   int,                           // message index in current sending chain
///   "pn":  int,                           // previous sending chain length
/// }
/// ```
class RatchetHeader {
  final List<int> dhPub; // sender's current ratchet X25519 public key
  final int       n;     // message number in current sending epoch
  final int       pn;    // previous epoch's message count (for skipped key recovery)

  const RatchetHeader({required this.dhPub, required this.n, required this.pn});

  Map<String, dynamic> toJson() => {
    'dh': base64Encode(dhPub),
    'n':  n,
    'pn': pn,
  };

  factory RatchetHeader.fromJson(Map<String, dynamic> json) => RatchetHeader(
    dhPub: base64Decode(json['dh'] as String),
    n:     json['n']  as int,
    pn:    json['pn'] as int,
  );

  String toBase64() => base64Encode(utf8.encode(jsonEncode(toJson())));

  factory RatchetHeader.fromBase64(String b64) =>
      RatchetHeader.fromJson(jsonDecode(utf8.decode(base64Decode(b64))) as Map<String, dynamic>);
}

// ══════════════════════════════════════════════════════════════════════════════
// Double Ratchet Session
// ══════════════════════════════════════════════════════════════════════════════

/// Full Signal Double Ratchet session state for a single peer conversation.
///
/// ## Ratchet Architecture
/// ```
///   X3DH SK ──► Root Key (RK)
///                  │
///         ┌────────┴──────────┐
///   DH Ratchet             Symmetric Ratchet
///         │                     │
///   KDF_RK(RK, DH)        KDF_CK(CK)
///   → new RK, new CK      → next CK, MK
/// ```
///
/// ## DH Ratchet trigger
/// When a new [RatchetHeader.dhPub] is received that differs from the stored
/// [_peerRatchetPub], a DH ratchet step is performed:
/// 1. Skip remaining keys in old receiving chain.
/// 2. Derive new receiving chain from new DH output.
/// 3. Generate a new local ratchet keypair.
/// 4. Derive new sending chain from new DH output.
class DoubleRatchetSession {
  final String conversationId;
  final String peerIdentityPublicKeyB64;

  // Ratchet state
  Uint8List    _rk;               // Root Key (32 bytes)
  Uint8List?   _cks;              // Sending Chain Key (null until first DH step)
  Uint8List?   _ckr;              // Receiving Chain Key (null until first message received)
  SimpleKeyPair _dhS;             // Local sending ratchet keypair
  List<int>?   _peerRatchetPub;   // Peer's last known ratchet public key

  int _ns  = 0;  // Send message counter (current epoch)
  int _nr  = 0;  // Receive message counter (current epoch)
  int _pns = 0;  // Previous send epoch message count

  final SkippedKeyStore _skipped = SkippedKeyStore();
  final _x25519 = X25519();
  final _aesGcm = AesGcm.with256bits();

  DoubleRatchetSession._({
    required this.conversationId,
    required this.peerIdentityPublicKeyB64,
    required this._rk,
    required this._dhS,
    this._cks,
    this._ckr,
    this._peerRatchetPub,
  });

  // ── Factory constructors ──────────────────────────────────────────────────

  /// Creates a session from the **Initiator (Alice)** perspective.
  ///
  /// Alice already ran X3DH and has [sk] (the shared secret). She also sends
  /// her initial ratchet public key [dhSPub] to Bob in the first message header,
  /// which Bob will use to complete his receive-side DH ratchet initialisation.
  ///
  /// Bob's initial ratchet public key = his SPK_pub (from the X3DH bundle).
  static Future<DoubleRatchetSession> initAlice({
    required String      conversationId,
    required String      peerIdentityPublicKeyB64,
    required Uint8List   sk,         // X3DH shared secret
    required List<int>   bobSpkPub,  // Bob's SPK_pub used as his initial ratchet pub
  }) async {
    final x25519 = X25519();
    // Alice generates her first sending ratchet keypair
    final dhS = await x25519.newKeyPair();
    // dhSPub is embedded dynamically inside encrypt() via _dhS.extractPublicKey()

    // Perform the first DH ratchet step to derive Alice's sending chain
    final bobRatchetPub = SimplePublicKey(bobSpkPub, type: KeyPairType.x25519);
    final dhOut         = await x25519.sharedSecretKey(keyPair: dhS, remotePublicKey: bobRatchetPub);
    final dhBytes       = await dhOut.extractBytes();
    final (newRk, newCks) = await kdfRk(sk, dhBytes);

    return DoubleRatchetSession._(
      conversationId:           conversationId,
      peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
      rk:            newRk,
      dhS:           dhS,
      cks:           newCks,
      ckr:           null,
      peerRatchetPub: bobSpkPub,
    );
  }

  /// Creates a session from the **Responder (Bob)** perspective.
  ///
  /// Bob uses his SPK private key as his initial ratchet keypair. He will perform
  /// the DH ratchet step on the first received message that contains Alice's ratchet pub.
  static Future<DoubleRatchetSession> initBob({
    required String      conversationId,
    required String      peerIdentityPublicKeyB64,
    required Uint8List   sk,         // X3DH shared secret
    required SimpleKeyPair spkBDh,   // Bob's SPK private key → initial ratchet keypair
  }) async {
    final spkPub = await spkBDh.extractPublicKey();
    return DoubleRatchetSession._(
      conversationId:           conversationId,
      peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
      rk:            sk,
      dhS:           spkBDh,        // Bob's initial sending ratchet = SPK
      cks:           null,          // No sending chain yet — Bob hasn't sent anything
      ckr:           null,          // No receive chain yet — awaiting Alice's first message
      peerRatchetPub: spkPub.bytes, // Bob knows his own SPK pub (will be replaced by Alice's)
    );
  }

  // ── Encryption ────────────────────────────────────────────────────────────

  /// Encrypts [plaintext] using the Double Ratchet.
  ///
  /// Returns a `"kamui_v4:<headerB64>:<nonceB64>:<ciphertextB64>"` wire string.
  ///
  /// - A DH ratchet step is performed automatically if needed (no sending chain yet).
  /// - The [RatchetHeader] contains `dhPub`, `n`, `pn` for the receiver's ratchet.
  Future<String> encrypt(String plaintext) async {
    if (_cks == null) {
      throw const RatchetException('No sending chain — session not fully initialized.');
    }

    // Symmetric-key ratchet step
    final (nextCks, mk) = await kdfCk(_cks!);
    _cks = nextCks;

    final dhSPub = await _dhS.extractPublicKey();
    final header = RatchetHeader(dhPub: dhSPub.bytes, n: _ns, pn: _pns);
    _ns++;

    // AES-256-GCM encrypt — header bytes are used as Additional Data for integrity
    final headerBytes = utf8.encode(header.toBase64());
    final secretKey   = SecretKey(mk);
    final nonce       = _aesGcm.newNonce();
    final secretBox   = await _aesGcm.encrypt(
      utf8.encode(plaintext),
      secretKey:          secretKey,
      nonce:              nonce,
      aad:                headerBytes,
    );

    final cipherAndMac = Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
    return 'kamui_v4:${header.toBase64()}:${base64Encode(nonce)}:${base64Encode(cipherAndMac)}';
  }

  // ── Decryption ────────────────────────────────────────────────────────────

  /// Decrypts a `"kamui_v4:..."` wire payload.
  ///
  /// ## Out-of-order recovery
  /// 1. If header DH key matches current receiving epoch AND `n < _nr`:
  ///    the message was delayed — retrieve from [SkippedKeyStore].
  /// 2. If header DH key is new: perform DH ratchet step, skip remaining keys
  ///    in old epoch (store them), then derive new receiving chain key.
  /// 3. Otherwise: advance symmetric ratchet normally.
  ///
  /// Returns decrypted [String] or throws [RatchetException].
  Future<String> decrypt(String wirePayload) async {
    try {
      return await _decryptInternal(wirePayload);
    } on RatchetException {
      rethrow;
    } catch (e) {
      throw RatchetException('Decryption error: $e');
    }
  }

  Future<String> _decryptInternal(String wirePayload) async {
    if (!wirePayload.startsWith('kamui_v4:')) {
      throw const RatchetException('Not a kamui_v4 wire payload.');
    }

    final parts = wirePayload.split(':');
    if (parts.length < 4) {
      throw const RatchetException('Malformed kamui_v4 payload — expected 4 segments.');
    }

    final headerB64     = parts[1];
    final nonceB64      = parts[2];
    final cipherB64     = parts[3];

    final header = RatchetHeader.fromBase64(headerB64);
    final nonce  = base64Decode(nonceB64);
    final cipherAndMac = base64Decode(cipherB64);

    const macLen   = 16;
    final cipherText = cipherAndMac.sublist(0, cipherAndMac.length - macLen);
    final macBytes   = cipherAndMac.sublist(cipherAndMac.length - macLen);

    // ── 1. Check skipped-key store (out-of-order) ─────────────────────────
    final skippedMk = _skipped.take(header.dhPub, header.n);
    if (skippedMk != null) {
      return _decryptWithKey(skippedMk, nonce, cipherText, macBytes, headerB64);
    }

    // ── 2. DH Ratchet step if peer's ratchet key changed ─────────────────
    final isNewDhEpoch = _peerRatchetPub == null ||
        !_listEqual(header.dhPub, _peerRatchetPub!);

    if (isNewDhEpoch) {
      // Skip remaining keys in old receive chain (store for out-of-order recovery)
      if (_ckr != null) {
        await _skipMessageKeys(_peerRatchetPub!, header.pn);
      }
      // DH Ratchet Step 1: derive new receive chain
      await _performDhRatchetReceive(header.dhPub);
      // Skip keys up to header.n in the new receive chain
      await _skipMessageKeys(header.dhPub, header.n);
    } else {
      // Same DH epoch — skip keys between _nr and header.n
      if (header.n < _nr) {
        throw RatchetException(
          'Message index ${header.n} already received (current: $_nr). '
          'Possible replay attack.',
        );
      }
      await _skipMessageKeys(header.dhPub, header.n);
    }

    // ── 3. Consume the next chain key to get message key ─────────────────
    if (_ckr == null) {
      throw const RatchetException('No receive chain available after ratchet step.');
    }
    final (nextCkr, mk) = await kdfCk(_ckr!);
    _ckr = nextCkr;
    _nr++;

    return _decryptWithKey(mk, nonce, cipherText, macBytes, headerB64);
  }

  // ── Accessors ─────────────────────────────────────────────────────────────

  /// The local sending ratchet public key — embedded in outgoing message headers.
  Future<List<int>> get localRatchetPub async {
    final pub = await _dhS.extractPublicKey();
    return pub.bytes;
  }

  /// Number of skipped message keys currently in the store.
  int get skippedKeyCount => _skipped.length;

  // ── Internal helpers ──────────────────────────────────────────────────────

  /// Performs a DH ratchet receive step, updating _rk and _ckr.
  /// Then generates a new local sending keypair and updates _rk and _cks.
  Future<void> _performDhRatchetReceive(List<int> newPeerPub) async {
    final remotePub = SimplePublicKey(newPeerPub, type: KeyPairType.x25519);

    // Step A: derive new receive chain from current local key × peer's new key
    final dhOutR = await _x25519.sharedSecretKey(keyPair: _dhS, remotePublicKey: remotePub);
    final (rkA, newCkr) = await kdfRk(_rk, await dhOutR.extractBytes());

    // Step B: generate new local sending ratchet keypair
    final newDhS    = await _x25519.newKeyPair();
    final dhOutS    = await _x25519.sharedSecretKey(keyPair: newDhS, remotePublicKey: remotePub);
    final (rkB, newCks) = await kdfRk(rkA, await dhOutS.extractBytes());

    // Commit state updates
    _pns            = _ns;
    _ns             = 0;
    _nr             = 0;
    _rk             = rkB;
    _cks            = newCks;
    _ckr            = newCkr;
    _dhS            = newDhS;
    _peerRatchetPub = newPeerPub;
  }

  /// Advances the receive chain from [_nr] up to (but not including) [targetN],
  /// storing each derived message key in [_skipped].
  Future<void> _skipMessageKeys(List<int> dhPub, int targetN) async {
    if (_ckr == null) return;
    final gap = targetN - _nr;
    if (gap > kMaxSkip) {
      throw RatchetException(
        'Receive gap $gap exceeds maximum skip limit $kMaxSkip — possible DoS.',
      );
    }
    while (_nr < targetN) {
      final (nextCkr, mk) = await kdfCk(_ckr!);
      final stored = _skipped.put(dhPub, _nr, mk);
      if (!stored) {
        throw const RatchetException(
          'Skipped key store full — cannot recover out-of-order message.',
        );
      }
      _ckr = nextCkr;
      _nr++;
    }
  }

  /// AES-256-GCM decryption with header as Additional Data (provides header authenticity).
  Future<String> _decryptWithKey(
    Uint8List   mk,
    List<int>   nonce,
    List<int>   cipherText,
    List<int>   macBytes,
    String      headerB64,
  ) async {
    try {
      final secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes));
      final clearBytes = await _aesGcm.decrypt(
        secretBox,
        secretKey: SecretKey(mk),
        aad:       utf8.encode(headerB64),
      );
      return utf8.decode(clearBytes);
    } catch (e) {
      throw RatchetException('AES-GCM decryption failed: $e');
    }
  }

  static bool _listEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Exception
// ══════════════════════════════════════════════════════════════════════════════

/// Thrown when a Double Ratchet operation cannot complete securely.
class RatchetException implements Exception {
  final String reason;
  const RatchetException(this.reason);

  @override
  String toString() => 'RatchetException: $reason';
}
