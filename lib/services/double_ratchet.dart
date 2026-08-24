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

/// Schema version of the serialized Double Ratchet persistence format.
const int kPersistentStateVersion = 1;

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

  /// Peeks the key for ([dhPub], [msgN]) without removing it.
  /// Returns `null` if not present or expired.
  Uint8List? peek(List<int> dhPub, int msgN) {
    _pruneExpired();
    final entry = _store[SkippedKeyIndex(dhPub, msgN)];
    return entry?.key;
  }

  /// Removes the key for ([dhPub], [msgN]) from the store.
  /// Returns `true` if the key was present and removed, `false` otherwise.
  bool remove(List<int> dhPub, int msgN) {
    _pruneExpired();
    return _store.remove(SkippedKeyIndex(dhPub, msgN)) != null;
  }

  /// Retrieves and removes the key for ([dhPub], [msgN]).
  /// Retained for convenience / backward compatibility.
  Uint8List? take(List<int> dhPub, int msgN) {
    _pruneExpired();
    final entry = _store.remove(SkippedKeyIndex(dhPub, msgN));
    return entry?.key;
  }

  /// Returns the number of currently stored skipped keys.
  int get length => _store.length;

  /// Clears all stored skipped keys.
  void clear() => _store.clear();

  /// Exports every live entry (including original creation timestamps) for
  /// encrypted persistence. Timestamps MUST survive a round-trip so TTL
  /// semantics remain intact across app restarts.
  List<Map<String, dynamic>> exportEntries() {
    _pruneExpired();
    return [
      for (final entry in _store.entries)
        <String, dynamic>{
          'dh':         base64Encode(entry.key.dhPub),
          'n':          entry.key.msgN,
          'key':        base64Encode(entry.value.key),
          'created_ms': entry.value.createdMs,
        },
    ];
  }

  /// Restores entries produced by [exportEntries], preserving their original
  /// creation timestamps. Throws [RatchetException] on any malformed input —
  /// callers treat the whole blob as corrupt and discard it (fail-closed).
  void restoreEntries(List<dynamic> entries) {
    for (final raw in entries) {
      if (raw is! Map<String, dynamic>) {
        throw const RatchetException('Malformed skipped-key entry: not an object.');
      }
      final dhB64     = raw['dh'];
      final msgN      = raw['n'];
      final keyB64    = raw['key'];
      final createdMs = raw['created_ms'];
      if (dhB64 is! String || msgN is! int || keyB64 is! String || createdMs is! int) {
        throw const RatchetException(
          'Malformed skipped-key entry: missing or invalid fields.',
        );
      }
      if (msgN < 0 || msgN > kMaxSkip) {
        throw RatchetException('Malformed skipped-key entry: invalid n=$msgN.');
      }
      final Uint8List dh;
      final Uint8List key;
      try {
        dh  = Uint8List.fromList(base64Decode(dhB64));
        key = Uint8List.fromList(base64Decode(keyB64));
      } catch (e) {
        throw RatchetException('Malformed skipped-key entry: bad Base64 ($e).');
      }
      if (dh.length != 32) {
        throw RatchetException(
          'Malformed skipped-key entry: dh length ${dh.length} (expected 32).',
        );
      }
      _store[SkippedKeyIndex(dh, msgN)] = _SkippedEntry(key, createdMs);
    }
  }

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
  final List<int> dhPub; // sender's current ratchet X25519 public key (32 bytes)
  final int       n;     // message number in current sending epoch
  final int       pn;    // previous epoch's message count (for skipped key recovery)

  RatchetHeader({required this.dhPub, required this.n, required this.pn}) {
    if (dhPub.length != 32) {
      throw RatchetException(
        'Invalid DH public key length: ${dhPub.length} (expected 32 bytes).',
      );
    }
    if (n < 0 || n > kMaxSkip) {
      throw RatchetException(
        'Invalid message counter n: $n (must be 0 <= n <= $kMaxSkip).',
      );
    }
    if (pn < 0 || pn > kMaxSkip) {
      throw RatchetException(
        'Invalid previous counter pn: $pn (must be 0 <= pn <= $kMaxSkip).',
      );
    }
  }

  Map<String, dynamic> toJson() => {
    'dh': base64Encode(dhPub),
    'n':  n,
    'pn': pn,
  };

  factory RatchetHeader.fromJson(Map<String, dynamic> json) {
    final dhVal = json['dh'];
    final nVal  = json['n'];
    final pnVal = json['pn'];

    if (dhVal is! String) {
      throw const RatchetException('Malformed RatchetHeader: missing or invalid "dh" field.');
    }
    if (nVal is! int) {
      throw const RatchetException('Malformed RatchetHeader: missing or invalid "n" field.');
    }
    if (pnVal is! int) {
      throw const RatchetException('Malformed RatchetHeader: missing or invalid "pn" field.');
    }

    final Uint8List dhBytes;
    try {
      dhBytes = base64Decode(dhVal);
    } catch (e) {
      throw RatchetException('Malformed RatchetHeader: "dh" is not valid Base64 ($e).');
    }

    return RatchetHeader(
      dhPub: dhBytes,
      n:     nVal,
      pn:    pnVal,
    );
  }

  String toBase64() => base64Encode(utf8.encode(jsonEncode(toJson())));

  factory RatchetHeader.fromBase64(String b64) {
    try {
      final jsonStr = utf8.decode(base64Decode(b64));
      final dynamic decoded = jsonDecode(jsonStr);
      if (decoded is! Map<String, dynamic>) {
        throw const RatchetException('Malformed RatchetHeader: root is not a JSON object.');
      }
      return RatchetHeader.fromJson(decoded);
    } on RatchetException {
      rethrow;
    } catch (e) {
      throw RatchetException('Failed to parse RatchetHeader from Base64: $e');
    }
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Candidate State (Transactional State Mutation)
// ══════════════════════════════════════════════════════════════════════════════

class _CandidateState {
  Uint8List rk;
  Uint8List? cks;
  Uint8List? ckr;
  SimpleKeyPair dhS;
  List<int>? peerRatchetPub;
  int ns;
  int nr;
  int pns;
  final List<({List<int> dhPub, int msgN, Uint8List key})> stagedSkippedKeys = [];

  _CandidateState({
    required this.rk,
    required this.cks,
    required this.ckr,
    required this.dhS,
    required this.peerRatchetPub,
    required this.ns,
    required this.nr,
    required this.pns,
  });
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
  /// ## Transactional State & Out-of-order recovery
  /// 1. If header DH key matches a key in [SkippedKeyStore]:
  ///    **Peek ➔ Authenticate ➔ Consume** (key removed ONLY upon MAC verification).
  /// 2. If header DH key is new: stage DH ratchet step & gap skips in [_CandidateState].
  /// 3. Otherwise: advance candidate symmetric ratchet.
  /// 4. Derive MK and attempt AES-256-GCM decryption.
  /// 5. On MAC success: **commit** candidate state to live state.
  /// 6. On MAC failure: **rollback** (discard candidate state with zero mutations).
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

    final headerB64 = parts[1];
    final nonceB64  = parts[2];
    final cipherB64 = parts[3];

    final RatchetHeader header;
    final Uint8List nonce;
    final Uint8List cipherAndMac;

    try {
      header       = RatchetHeader.fromBase64(headerB64);
      nonce        = Uint8List.fromList(base64Decode(nonceB64));
      cipherAndMac = Uint8List.fromList(base64Decode(cipherB64));
    } on RatchetException {
      rethrow;
    } catch (e) {
      throw RatchetException('Malformed payload encoding: $e');
    }

    const macLen = 16;
    if (cipherAndMac.length < macLen) {
      throw const RatchetException('Ciphertext shorter than MAC length (16 bytes).');
    }
    final cipherText = cipherAndMac.sublist(0, cipherAndMac.length - macLen);
    final macBytes   = cipherAndMac.sublist(cipherAndMac.length - macLen);

    // ── 1. Check skipped-key store (Peek ➔ Authenticate ➔ Consume) ────────
    final skippedMk = _skipped.peek(header.dhPub, header.n);
    if (skippedMk != null) {
      final plaintext = await _decryptWithKey(
        skippedMk,
        nonce,
        cipherText,
        macBytes,
        headerB64,
      );
      // MAC authenticated successfully! Now consume from store.
      _skipped.remove(header.dhPub, header.n);
      return plaintext;
    }

    // ── 2. Transactional Ratchet State Machine (Candidate State) ──────────
    final isNewDhEpoch = _peerRatchetPub == null ||
        !_listEqual(header.dhPub, _peerRatchetPub!);

    final candidate = _CandidateState(
      rk:             Uint8List.fromList(_rk),
      cks:            _cks != null ? Uint8List.fromList(_cks!) : null,
      ckr:            _ckr != null ? Uint8List.fromList(_ckr!) : null,
      dhS:            _dhS,
      peerRatchetPub: _peerRatchetPub != null ? List<int>.from(_peerRatchetPub!) : null,
      ns:             _ns,
      nr:             _nr,
      pns:            _pns,
    );

    final Uint8List mk;

    if (isNewDhEpoch) {
      // Step A: Skip remaining keys in old receive chain up to header.pn
      if (candidate.ckr != null && candidate.peerRatchetPub != null) {
        await _skipMessageKeysCandidate(candidate, candidate.peerRatchetPub!, header.pn);
      }

      // Step B: Derive new receive chain & new sending chain
      final remotePub = SimplePublicKey(header.dhPub, type: KeyPairType.x25519);

      // Derive new receive chain from current local key × peer's new key
      final dhOutR = await _x25519.sharedSecretKey(keyPair: candidate.dhS, remotePublicKey: remotePub);
      final (rkA, newCkr) = await kdfRk(candidate.rk, await dhOutR.extractBytes());

      // Generate new local sending ratchet keypair & derive new sending chain
      final newDhS = await _x25519.newKeyPair();
      final dhOutS = await _x25519.sharedSecretKey(keyPair: newDhS, remotePublicKey: remotePub);
      final (rkB, newCks) = await kdfRk(rkA, await dhOutS.extractBytes());

      // Update candidate state
      candidate.pns            = candidate.ns;
      candidate.ns             = 0;
      candidate.nr             = 0;
      candidate.rk             = rkB;
      candidate.cks            = newCks;
      candidate.ckr            = newCkr;
      candidate.dhS            = newDhS;
      candidate.peerRatchetPub = List<int>.from(header.dhPub);

      // Step C: Skip keys in new receive chain up to header.n
      await _skipMessageKeysCandidate(candidate, header.dhPub, header.n);

      // Step D: Advance candidate receive chain for current message
      if (candidate.ckr == null) {
        throw const RatchetException('No receive chain available after ratchet step.');
      }
      final (nextCkr, derivedMk) = await kdfCk(candidate.ckr!);
      candidate.ckr = nextCkr;
      candidate.nr++;
      mk = derivedMk;
    } else {
      // Same DH epoch
      if (header.n < candidate.nr) {
        throw RatchetException(
          'Message index ${header.n} already received (current: ${candidate.nr}). '
          'Possible replay attack.',
        );
      }

      // Skip keys up to header.n
      await _skipMessageKeysCandidate(candidate, header.dhPub, header.n);

      if (candidate.ckr == null) {
        throw const RatchetException('No receive chain available in current epoch.');
      }
      final (nextCkr, derivedMk) = await kdfCk(candidate.ckr!);
      candidate.ckr = nextCkr;
      candidate.nr++;
      mk = derivedMk;
    }

    // ── 3. Attempt Decryption (MAC verification) ───────────────────────────
    // If decryption fails, _decryptWithKey throws RatchetException.
    // The candidate state is completely discarded with ZERO mutation to live state!
    final plaintext = await _decryptWithKey(
      mk,
      nonce,
      cipherText,
      macBytes,
      headerB64,
    );

    // ── 4. COMMIT TRANSACTION (Authentication Succeeded) ──────────────────
    // Stage all skipped keys into persistent store
    for (final staged in candidate.stagedSkippedKeys) {
      final stored = _skipped.put(staged.dhPub, staged.msgN, staged.key);
      if (!stored) {
        throw const RatchetException(
          'Skipped key store full — cannot store skipped message keys.',
        );
      }
    }

    // Atomically commit candidate state to live session state
    _rk             = candidate.rk;
    _cks            = candidate.cks;
    _ckr            = candidate.ckr;
    _dhS            = candidate.dhS;
    _peerRatchetPub = candidate.peerRatchetPub;
    _ns             = candidate.ns;
    _nr             = candidate.nr;
    _pns            = candidate.pns;

    return plaintext;
  }

  // ── Accessors ─────────────────────────────────────────────────────────────

  /// The local sending ratchet public key — embedded in outgoing message headers.
  Future<List<int>> get localRatchetPub async {
    final pub = await _dhS.extractPublicKey();
    return pub.bytes;
  }

  /// Number of skipped message keys currently in the store.
  int get skippedKeyCount => _skipped.length;

  // ── Persistence (serialize ONLY at transactional commit points) ──────────

  /// Serializes the complete ratchet state for encrypted persistence.
  ///
  /// **SECURITY INVARIANT**: callers MUST invoke this only AFTER a transactional
  /// commit (post-encryption, post-authenticated-decrypt, or session creation).
  /// Serializing candidate state would persist unauthenticated key material and
  /// break the rollback guarantees of [decrypt].
  ///
  /// Format version 1 covers: root key, both chain keys, the local ratchet
  /// keypair (private + public), peer ratchet public, all counters, and every
  /// skipped message key with its original TTL creation timestamp.
  Future<Map<String, dynamic>> toPersistentJson() async {
    final dhSPub  = await _dhS.extractPublicKey();
    final dhSPriv = await _dhS.extractPrivateKeyBytes();

    return <String, dynamic>{
      'version':          kPersistentStateVersion,
      'conversation_id':  conversationId,
      'peer_ik':          peerIdentityPublicKeyB64,
      'rk':               base64Encode(_rk),
      if (_cks != null) 'cks': base64Encode(_cks!),
      if (_ckr != null) 'ckr': base64Encode(_ckr!),
      'dh_s_priv':        base64Encode(dhSPriv),
      'dh_s_pub':         base64Encode(dhSPub.bytes),
      if (_peerRatchetPub != null)
        'peer_ratchet_pub': base64Encode(_peerRatchetPub!),
      'ns':               _ns,
      'nr':               _nr,
      'pns':              _pns,
      'skipped':          _skipped.exportEntries(),
    };
  }

  /// Reconstructs a session from [toPersistentJson] output.
  ///
  /// Throws [RatchetException] on ANY malformation — callers must treat the
  /// entire blob as corrupt, discard it, and re-establish via fresh X3DH.
  /// Never partial: either a fully valid session is returned or an exception.
  static Future<DoubleRatchetSession> fromPersistentJson(
    Map<String, dynamic> json,
  ) async {
    if (json['version'] != kPersistentStateVersion) {
      throw RatchetException(
        'Unsupported persistent ratchet state version: ${json['version']} '
        '(expected $kPersistentStateVersion).',
      );
    }

    final conversationId = json['conversation_id'];
    final peerIk         = json['peer_ik'];
    final rkB64          = json['rk'];
    final dhSPrivB64     = json['dh_s_priv'];
    final dhSPubB64      = json['dh_s_pub'];
    final ns             = json['ns'];
    final nr             = json['nr'];
    final pns            = json['pns'];
    final skipped        = json['skipped'];

    if (conversationId is! String || conversationId.isEmpty) {
      throw const RatchetException('Malformed persistent state: conversation_id.');
    }
    if (peerIk is! String || peerIk.isEmpty) {
      throw const RatchetException('Malformed persistent state: peer_ik.');
    }
    if (rkB64 is! String || dhSPrivB64 is! String || dhSPubB64 is! String) {
      throw const RatchetException('Malformed persistent state: missing key material.');
    }
    if (ns is! int || nr is! int || pns is! int || ns < 0 || nr < 0 || pns < 0) {
      throw const RatchetException('Malformed persistent state: counters.');
    }
    if (skipped is! List<dynamic>) {
      throw const RatchetException('Malformed persistent state: skipped keys.');
    }

    final Uint8List rk;
    final Uint8List dhSPriv;
    final Uint8List dhSPub;
    try {
      rk      = Uint8List.fromList(base64Decode(rkB64));
      dhSPriv = Uint8List.fromList(base64Decode(dhSPrivB64));
      dhSPub  = Uint8List.fromList(base64Decode(dhSPubB64));
    } catch (e) {
      throw RatchetException('Malformed persistent state: bad Base64 ($e).');
    }

    if (rk.length != 32) {
      throw RatchetException('Malformed persistent state: rk length ${rk.length}.');
    }
    if (dhSPriv.length != 32 || dhSPub.length != 32) {
      throw RatchetException(
        'Malformed persistent state: dhS lengths priv=${dhSPriv.length} pub=${dhSPub.length}.',
      );
    }

    Uint8List? cks;
    Uint8List? ckr;
    List<int>? peerRatchetPub;
    try {
      if (json['cks'] is String) {
        cks = Uint8List.fromList(base64Decode(json['cks'] as String));
      }
      if (json['ckr'] is String) {
        ckr = Uint8List.fromList(base64Decode(json['ckr'] as String));
      }
      if (json['peer_ratchet_pub'] is String) {
        peerRatchetPub = base64Decode(json['peer_ratchet_pub'] as String);
      }
    } catch (e) {
      throw RatchetException('Malformed persistent state: optional fields ($e).');
    }
    if (cks != null && cks.length != 32) {
      throw RatchetException('Malformed persistent state: cks length ${cks.length}.');
    }
    if (ckr != null && ckr.length != 32) {
      throw RatchetException('Malformed persistent state: ckr length ${ckr.length}.');
    }
    if (peerRatchetPub != null && peerRatchetPub.length != 32) {
      throw RatchetException(
        'Malformed persistent state: peer_ratchet_pub length ${peerRatchetPub.length}.',
      );
    }

    final dhS = SimpleKeyPairData(
      dhSPriv,
      publicKey: SimplePublicKey(dhSPub, type: KeyPairType.x25519),
      type:      KeyPairType.x25519,
    );

    final session = DoubleRatchetSession._(
      conversationId:           conversationId,
      peerIdentityPublicKeyB64: peerIk,
      rk:            rk,
      dhS:           dhS,
      cks:           cks,
      ckr:           ckr,
      peerRatchetPub: peerRatchetPub,
    );
    session._ns  = ns;
    session._nr  = nr;
    session._pns = pns;

    // Restore skipped keys — throws on malformation (whole blob discarded).
    session._skipped.restoreEntries(skipped);

    return session;
  }

  // ── Internal helpers ──────────────────────────────────────────────────────

  /// Advances candidate receive chain from [candidate.nr] up to [targetN],
  /// staging derived message keys in [candidate.stagedSkippedKeys].
  Future<void> _skipMessageKeysCandidate(
    _CandidateState candidate,
    List<int>       dhPub,
    int             targetN,
  ) async {
    if (candidate.ckr == null) return;
    if (targetN < candidate.nr) return;
    final gap = targetN - candidate.nr;
    if (gap > kMaxSkip) {
      throw RatchetException(
        'Receive gap $gap exceeds maximum skip limit $kMaxSkip — possible DoS.',
      );
    }
    while (candidate.nr < targetN) {
      final (nextCkr, mk) = await kdfCk(candidate.ckr!);
      candidate.stagedSkippedKeys.add((
        dhPub: List<int>.from(dhPub),
        msgN:  candidate.nr,
        key:   mk,
      ));
      candidate.ckr = nextCkr;
      candidate.nr++;
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
