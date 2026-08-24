import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'x3dh_service.dart';

/// Number of One-Time PreKeys maintained in the local pool.
///
/// All `(id → pub)` pairs are embedded in every published PreKeyBundle so ONE
/// QR exchange satisfies multiple offline handshakes. [IdentityKeyService]
/// replenishes the pool back to this size after every consumption.
const int kOpkPoolSize = 8;

// ══════════════════════════════════════════════════════════════════════════════
// IdentityKeyService
// ══════════════════════════════════════════════════════════════════════════════

/// Manages all long-term and medium-term cryptographic identity keys for a Kamui node.
///
/// ## Key Inventory (Kamui v3 / X3DH)
/// | Key         | Algorithm | Purpose                        | Storage alias              |
/// |-------------|-----------|--------------------------------|----------------------------|
/// | IK_ed       | Ed25519   | Identity signing (SPK binding) | kamui_ik_ed25519_priv/pub  |
/// | IK_dh       | X25519    | Identity DH (X3DH DH1/DH2)    | kamui_ik_x25519_priv/pub   |
/// | SPK         | X25519    | Signed PreKey (DH1/DH3)        | kamui_spk_x25519_priv/pub  |
/// | SPK_sig     | Ed25519   | Signature of SPK_pub by IK_ed  | kamui_spk_sig              |
/// | OPK         | X25519    | One-Time PreKey (DH4, optional)| kamui_opk_x25519_priv/pub  |
class IdentityKeyService {
  static final IdentityKeyService _instance = IdentityKeyService._internal();
  factory IdentityKeyService() => _instance;

  final FlutterSecureStorage _secureStorage;

  IdentityKeyService._internal({FlutterSecureStorage? secureStorage})
      : _secureStorage = secureStorage ?? const FlutterSecureStorage(
          aOptions: AndroidOptions(encryptedSharedPreferences: true),
          iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
        );

  /// Factory for isolated instances in tests or multi-identity scenarios.
  factory IdentityKeyService.isolated({FlutterSecureStorage? secureStorage}) {
    return IdentityKeyService._internal(secureStorage: secureStorage);
  }

  // ─── Storage key aliases ──────────────────────────────────────────────────
  static const _ikEdPrivAlias  = 'kamui_ik_ed25519_priv';
  static const _ikEdPubAlias   = 'kamui_ik_ed25519_pub';
  static const _ikDhPrivAlias  = 'kamui_ik_x25519_priv';
  static const _ikDhPubAlias   = 'kamui_ik_x25519_pub';
  static const _spkPrivAlias   = 'kamui_spk_x25519_priv';
  static const _spkPubAlias    = 'kamui_spk_x25519_pub';
  static const _spkSigAlias    = 'kamui_spk_sig';
  static const _opkPrivAlias   = 'kamui_opk_x25519_priv';
  static const _opkPubAlias    = 'kamui_opk_x25519_pub';
  static const _opkIdAlias     = 'kamui_current_opk_id';
  static const _opkRegistryAlias = 'kamui_opk_registry';

  // ─── Algorithms ──────────────────────────────────────────────────────────
  final _ed25519 = Ed25519();
  final _x25519  = X25519();

  // ─── In-memory state ──────────────────────────────────────────────────────
  SimpleKeyPair? _ikEdKeyPair;   // Ed25519 identity (signing)
  SimpleKeyPair? _ikDhKeyPair;   // X25519 identity (DH)
  SimpleKeyPair? _spkKeyPair;    // X25519 Signed PreKey
  List<int>?    _spkSigBytes;   // Ed25519 signature over SPK_pub
  
  // OPK pool state (Phase 4 Invariants + Phase 2 pool expansion)
  final Map<int, SimpleKeyPair> _opkStore = {};
  final Set<int> _consumedOpkIds = {};
  int? _currentOpkId;

  /// Cached base64 public keys per live OPK id — lets the synchronous bundle
  /// builder expose the full pool without async key extraction.
  final Map<int, String> _opkPubB64ById = {};

  String? _ikEdPubB64;
  String? _ikDhPubB64;
  String? _spkPubB64;
  String? _opkPubB64;

  bool _isInitialized = false;
  bool get isInitialized => _isInitialized;

  // ─── Public accessors ─────────────────────────────────────────────────────

  /// Ed25519 identity public key (base64) — signing surface.
  String? get identityEdPublicKeyB64 => _ikEdPubB64;

  /// X25519 identity DH public key (base64) — used in X3DH DH1/DH2.
  String? get identityDhPublicKeyB64 => _ikDhPubB64;

  /// Ed25519 identity key pair — signing surface.
  SimpleKeyPair? get ikEdKeyPair => _ikEdKeyPair;

  /// X25519 identity DH key pair — required by [SessionManager] for X3DH.
  SimpleKeyPair? get ikDhKeyPair => _ikDhKeyPair;

  /// X25519 Signed PreKey pair — required by [SessionManager] for X3DH responder.
  SimpleKeyPair? get spkKeyPair => _spkKeyPair;

  /// Active X25519 One-Time PreKey pair (nullable).
  SimpleKeyPair? get opkKeyPair => _currentOpkId != null ? _opkStore[_currentOpkId!] : null;

  /// Active One-Time PreKey identifier.
  int? get currentOpkId => _currentOpkId;

  /// Retrieves an OPK keypair by [opkId] if available and not yet consumed.
  /// Throws [X3dhException] if the key was already consumed (replay/reuse attempt)
  /// or if [opkId] is invalid.
  SimpleKeyPair? getOpk(int opkId) {
    if (_consumedOpkIds.contains(opkId)) {
      throw X3dhException('One-time prekey (ID: $opkId) has already been consumed (replay/reuse detected).');
    }
    if (!_opkStore.containsKey(opkId)) {
      throw X3dhException('Unknown or invalid one-time prekey ID: $opkId.');
    }
    return _opkStore[opkId];
  }

  /// Consumes [opkId] exactly once upon authenticated handshake completion.
  ///
  /// After consumption the pool is replenished back to [kOpkPoolSize] so a
  /// single published bundle keeps satisfying multiple offline handshakes.
  Future<void> consumeOpk(int opkId) async {
    if (_consumedOpkIds.contains(opkId)) {
      throw X3dhException('One-time prekey (ID: $opkId) is already consumed.');
    }
    if (!_opkStore.containsKey(opkId)) {
      throw X3dhException('Cannot consume unknown one-time prekey ID: $opkId.');
    }

    _opkStore.remove(opkId);
    _opkPubB64ById.remove(opkId);
    _consumedOpkIds.add(opkId);

    // Erase from secure storage
    await _secureStorage.delete(key: 'kamui_opk_${opkId}_priv');
    await _secureStorage.delete(key: 'kamui_opk_${opkId}_pub');

    if (_currentOpkId == opkId) {
      _currentOpkId = null;
      _opkPubB64 = null;
    }

    // Maintain pool size + repoint the legacy mirror at a live key.
    await _replenishPool();
  }

  /// Tops the OPK pool up to [kOpkPoolSize] and refreshes legacy mirror state.
  Future<void> _replenishPool() async {
    while (_opkStore.length < kOpkPoolSize) {
      await generateNewOpk();
    }
    if (_currentOpkId == null || !_opkStore.containsKey(_currentOpkId)) {
      final liveIds = _opkStore.keys.toList()..sort();
      if (liveIds.isNotEmpty) {
        final id  = liveIds.first;
        final pub = await _opkStore[id]!.extractPublicKey();
        _currentOpkId = id;
        _opkPubB64    = base64Encode(pub.bytes);
        await _secureStorage.write(key: _opkIdAlias,   value: id.toString());
        await _secureStorage.write(key: _opkPrivAlias,
            value: base64Encode(await _opkStore[id]!.extractPrivateKeyBytes()));
        await _secureStorage.write(key: _opkPubAlias,  value: _opkPubB64!);
      }
    }
    await _persistRegistry();
  }

  /// Generates a new fresh OPK in the pool with an incremented ID.
  Future<int> generateNewOpk() async {
    final maxId = _opkStore.keys
        .followedBy(_consumedOpkIds)
        .fold(0, (max, id) => id > max ? id : max);
    final nextId = maxId + 1;
    final opkKP  = await _x25519.newKeyPair();
    final opkPub = await opkKP.extractPublicKey();
    final opkPriv = await opkKP.extractPrivateKeyBytes();

    await _secureStorage.write(key: 'kamui_opk_${nextId}_priv', value: base64Encode(opkPriv));
    await _secureStorage.write(key: 'kamui_opk_${nextId}_pub',  value: base64Encode(opkPub.bytes));
    await _secureStorage.write(key: _opkIdAlias, value: nextId.toString());

    _opkStore[nextId] = opkKP;
    _opkPubB64ById[nextId] = base64Encode(opkPub.bytes);
    _currentOpkId = nextId;
    _opkPubB64 = base64Encode(opkPub.bytes);
    return nextId;
  }

  /// Persists the live/consumed OPK id registry so the pool (and replay
  /// protection for consumed ids) survives app restarts.
  Future<void> _persistRegistry() async {
    await _secureStorage.write(
      key: _opkRegistryAlias,
      value: jsonEncode({
        'live':     _opkStore.keys.toList()..sort(),
        'consumed': _consumedOpkIds.toList()..sort(),
      }),
    );
  }

  /// Legacy accessor — returns the X25519 DH identity keypair.
  /// Kept for [SessionManager] v2 backward compatibility.
  SimpleKeyPair? get keyPair => _ikDhKeyPair;

  /// Legacy accessor — returns X25519 DH public key as base64.
  String? get identityPublicKeyB64 => _ikDhPubB64;

  // ─── Lifecycle ────────────────────────────────────────────────────────────

  /// Loads all identity keys from secure storage, or generates a fresh keyset.
  Future<void> init() async {
    if (_isInitialized) return;

    final ikEdPrivB64 = await _secureStorage.read(key: _ikEdPrivAlias);
    final ikEdPubB64  = await _secureStorage.read(key: _ikEdPubAlias);
    final ikDhPrivB64 = await _secureStorage.read(key: _ikDhPrivAlias);
    final ikDhPubB64  = await _secureStorage.read(key: _ikDhPubAlias);
    final spkPrivB64  = await _secureStorage.read(key: _spkPrivAlias);
    final spkPubB64   = await _secureStorage.read(key: _spkPubAlias);
    final spkSigB64   = await _secureStorage.read(key: _spkSigAlias);
    final opkIdStr    = await _secureStorage.read(key: _opkIdAlias);
    final opkPrivB64  = await _secureStorage.read(key: _opkPrivAlias);
    final opkPubB64   = await _secureStorage.read(key: _opkPubAlias);

    final allPresent = ikEdPrivB64 != null && ikEdPubB64  != null &&
                       ikDhPrivB64 != null && ikDhPubB64  != null &&
                       spkPrivB64  != null && spkPubB64   != null &&
                       spkSigB64   != null;

    if (allPresent) {
      _ikEdKeyPair = SimpleKeyPairData(
        base64Decode(ikEdPrivB64),
        publicKey: SimplePublicKey(base64Decode(ikEdPubB64), type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      );
      _ikEdPubB64 = ikEdPubB64;

      _ikDhKeyPair = SimpleKeyPairData(
        base64Decode(ikDhPrivB64),
        publicKey: SimplePublicKey(base64Decode(ikDhPubB64), type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );
      _ikDhPubB64 = ikDhPubB64;

      _spkKeyPair = SimpleKeyPairData(
        base64Decode(spkPrivB64),
        publicKey: SimplePublicKey(base64Decode(spkPubB64), type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );
      _spkPubB64   = spkPubB64;
      _spkSigBytes = base64Decode(spkSigB64);

      final activeId = int.tryParse(opkIdStr ?? '1') ?? 1;

      final registryRaw = await _secureStorage.read(key: _opkRegistryAlias);
      if (registryRaw != null) {
        // ── Pool-aware restore (v3 keysets) ────────────────────────────────
        try {
          final reg = jsonDecode(registryRaw) as Map<String, dynamic>;
          final liveIds =
              (reg['live'] as List<dynamic>? ?? []).whereType<int>().toSet();
          _consumedOpkIds.addAll(
            (reg['consumed'] as List<dynamic>? ?? []).whereType<int>(),
          );
          for (final id in liveIds) {
            final priv = await _secureStorage.read(key: 'kamui_opk_${id}_priv');
            final pub  = await _secureStorage.read(key: 'kamui_opk_${id}_pub');
            if (priv != null && pub != null) {
              _opkStore[id] = SimpleKeyPairData(
                base64Decode(priv),
                publicKey: SimplePublicKey(base64Decode(pub), type: KeyPairType.x25519),
                type: KeyPairType.x25519,
              );
              _opkPubB64ById[id] = pub;
            }
          }
        } catch (_) {
          // Corrupt registry → fall through to legacy single-OPK restore.
          _opkStore.clear();
          _consumedOpkIds.clear();
          _opkPubB64ById.clear();
        }
      }

      if (_opkStore.isEmpty) {
        // ── Legacy single-OPK restore (pre-pool keysets) ───────────────────
        if (opkPrivB64 != null && opkPubB64 != null) {
          final opkKp = SimpleKeyPairData(
            base64Decode(opkPrivB64),
            publicKey: SimplePublicKey(base64Decode(opkPubB64), type: KeyPairType.x25519),
            type: KeyPairType.x25519,
          );
          _opkStore[activeId] = opkKp;
          _opkPubB64ById[activeId] = opkPubB64;
          _currentOpkId = activeId;
          _opkPubB64 = opkPubB64;
        }
      } else if (_opkStore.containsKey(activeId)) {
        _currentOpkId = activeId;
        _opkPubB64 = _opkPubB64ById[activeId];
      }

      // Top the pool up to [kOpkPoolSize] — covers pre-pool keyset upgrades
      // and partially-consumed pools after restart.
      await _replenishPool();
    } else {
      await _generateFullKeyset();
    }

    _isInitialized = true;
  }

  /// Generates a complete fresh keyset: IK_ed, IK_dh, SPK (signed), OPK.
  Future<void> _generateFullKeyset() async {
    // 1. Ed25519 Identity Key (signing)
    final ikEdKP  = await _ed25519.newKeyPair();
    final ikEdPub = await ikEdKP.extractPublicKey();
    final ikEdPriv = await ikEdKP.extractPrivateKeyBytes();

    // 2. X25519 Identity DH Key
    final ikDhKP  = await _x25519.newKeyPair();
    final ikDhPub = await ikDhKP.extractPublicKey();
    final ikDhPriv = await ikDhKP.extractPrivateKeyBytes();

    // 3. X25519 Signed PreKey
    final spkKP  = await _x25519.newKeyPair();
    final spkPub = await spkKP.extractPublicKey();
    final spkPriv = await spkKP.extractPrivateKeyBytes();

    // 4. Sign SPK_pub with IK_ed_priv
    final spkSig = await _ed25519.sign(spkPub.bytes, keyPair: ikEdKP);

    // 5. X25519 One-Time PreKey pool (N = kOpkPoolSize, IDs 1..N).
    //    The whole pool is published in QR bundles so ONE exchange satisfies
    //    multiple offline handshakes; consumption replenishes back to N.
    const initialOpkId = 1;
    for (var i = 1; i <= kOpkPoolSize; i++) {
      final opkKP   = await _x25519.newKeyPair();
      final opkPub  = await opkKP.extractPublicKey();
      final opkPriv = await opkKP.extractPrivateKeyBytes();

      await _secureStorage.write(key: 'kamui_opk_${i}_priv', value: base64Encode(opkPriv));
      await _secureStorage.write(key: 'kamui_opk_${i}_pub',  value: base64Encode(opkPub.bytes));

      _opkStore[i] = opkKP;
      _opkPubB64ById[i] = base64Encode(opkPub.bytes);
    }

    // Persist to secure storage
    await _secureStorage.write(key: _ikEdPrivAlias, value: base64Encode(ikEdPriv));
    await _secureStorage.write(key: _ikEdPubAlias,  value: base64Encode(ikEdPub.bytes));
    await _secureStorage.write(key: _ikDhPrivAlias, value: base64Encode(ikDhPriv));
    await _secureStorage.write(key: _ikDhPubAlias,  value: base64Encode(ikDhPub.bytes));
    await _secureStorage.write(key: _spkPrivAlias,  value: base64Encode(spkPriv));
    await _secureStorage.write(key: _spkPubAlias,   value: base64Encode(spkPub.bytes));
    await _secureStorage.write(key: _spkSigAlias,   value: base64Encode(spkSig.bytes));

    // Legacy single-OPK mirror points at ID 1 for backward compatibility.
    final initialOpkPubB64 = _opkPubB64ById[initialOpkId]!;
    final initialOpkPriv = await _opkStore[initialOpkId]!.extractPrivateKeyBytes();
    await _secureStorage.write(key: _opkIdAlias,    value: initialOpkId.toString());
    await _secureStorage.write(key: _opkPrivAlias,  value: base64Encode(initialOpkPriv));
    await _secureStorage.write(key: _opkPubAlias,   value: initialOpkPubB64);
    await _persistRegistry();

    // Update in-memory state
    _ikEdKeyPair  = ikEdKP;
    _ikEdPubB64   = base64Encode(ikEdPub.bytes);
    _ikDhKeyPair  = ikDhKP;
    _ikDhPubB64   = base64Encode(ikDhPub.bytes);
    _spkKeyPair   = spkKP;
    _spkPubB64    = base64Encode(spkPub.bytes);
    _spkSigBytes  = spkSig.bytes;
    _currentOpkId = initialOpkId;
    _opkPubB64    = initialOpkPubB64;
  }

  /// Force-generates a new complete keyset (e.g. duress wipe, key rotation).
  Future<void> generateNewIdentityKeyPair() async {
    await _generateFullKeyset();
    _isInitialized = true;
  }

  /// Builds the local [PreKeyBundle] for sharing with peers (synchronous).
  /// Includes the full OPK pool via cached public keys. For the async variant
  /// that extracts keys directly from keypairs, call [generatePreKeyBundleAsync].
  PreKeyBundle? generatePreKeyBundle() {
    final edPubB64 = _ikEdPubB64;
    final dhPubB64 = _ikDhPubB64;
    final spPubB64 = _spkPubB64;
    final spkSig   = _spkSigBytes;

    if (edPubB64 == null || dhPubB64 == null || spPubB64 == null || spkSig == null) {
      return null;
    }

    return PreKeyBundle(
      ikPubEd: base64Decode(edPubB64),
      ikPubDh: base64Decode(dhPubB64),
      spkPub:  base64Decode(spPubB64),
      spkSig:  spkSig,
      opkId:   _currentOpkId,
      opkPub:  _opkPubB64 != null ? base64Decode(_opkPubB64!) : null,
      opks: {
        for (final entry in _opkPubB64ById.entries)
          entry.key: base64Decode(entry.value),
      },
    );
  }

  /// Async version that correctly extracts the OPK public keys.
  Future<PreKeyBundle?> generatePreKeyBundleAsync() async {
    if (_ikEdKeyPair == null || _ikDhKeyPair == null ||
        _spkKeyPair  == null || _spkSigBytes == null) {
      return null;
    }

    final ikEdPub = await _ikEdKeyPair!.extractPublicKey();
    final ikDhPub = await _ikDhKeyPair!.extractPublicKey();
    final spkPub  = await _spkKeyPair!.extractPublicKey();

    List<int>? opkPubBytes;
    if (_currentOpkId != null && _opkStore.containsKey(_currentOpkId)) {
      final opkPub = await _opkStore[_currentOpkId!]!.extractPublicKey();
      opkPubBytes  = opkPub.bytes;
      _opkPubB64ById[_currentOpkId!] = base64Encode(opkPub.bytes);
    }

    // Full pool — extract any missing public keys directly from keypairs.
    final poolPubs = <int, List<int>>{};
    for (final entry in _opkStore.entries) {
      final cached = _opkPubB64ById[entry.key];
      if (cached != null) {
        poolPubs[entry.key] = base64Decode(cached);
      } else {
        final pub = await entry.value.extractPublicKey();
        _opkPubB64ById[entry.key] = base64Encode(pub.bytes);
        poolPubs[entry.key] = pub.bytes;
      }
    }

    return PreKeyBundle(
      ikPubEd: ikEdPub.bytes,
      ikPubDh: ikDhPub.bytes,
      spkPub:  spkPub.bytes,
      spkSig:  _spkSigBytes!,
      opkId:   _currentOpkId,
      opkPub:  opkPubBytes,
      opks:    poolPubs,
    );
  }

  // ─── Handshake Payload (QR exchange) ─────────────────────────────────────

  /// Generates a v3 JSON Handshake Payload embedding the full PreKeyBundle.
  ///
  /// Wire format:
  /// ```json
  /// {
  ///   "v": 3,
  ///   "dest": "<I2P destination key>",
  ///   "ik_ed":   "<base64 Ed25519 pub>",
  ///   "ik_dh":   "<base64 X25519 DH pub>",
  ///   "spk":     "<base64 X25519 SPK pub>",
  ///   "spk_sig": "<base64 Ed25519 sig of SPK pub>",
  ///   "opk_id":  1,                          // optional (legacy mirror)
  ///   "opk":     "<base64 X25519 OPK pub>",  // optional (legacy mirror)
  ///   "opks":    {"1": "<b64 pub>", ...}     // optional full OPK pool
  /// }
  /// ```
  Future<String> generateHandshakePayloadAsync(String destinationKey) async {
    final bundle = await generatePreKeyBundleAsync();
    if (bundle == null) {
      // Fallback: v2-compatible payload if keys not initialized
      return jsonEncode({'v': 2, 'dest': destinationKey, 'id_pub': _ikDhPubB64 ?? ''});
    }
    return jsonEncode({
      'v':    3,
      'dest': destinationKey,
      ...bundle.toJson(),
    });
  }

  /// Synchronous wrapper — returns v3 payload when keys are loaded, v2 otherwise.
  /// Used by [QrShareDialog] which calls this from a synchronous build context.
  String generateHandshakePayload(String destinationKey) {
    if (_ikEdPubB64 == null || _ikDhPubB64 == null ||
        _spkPubB64  == null || _spkSigBytes == null) {
      // Fallback to v2 if not yet initialized
      return jsonEncode({'v': 2, 'dest': destinationKey, 'id_pub': _ikDhPubB64 ?? ''});
    }
    return jsonEncode({
      'v':       3,
      'dest':    destinationKey,
      'ik_ed':   _ikEdPubB64,
      'ik_dh':   _ikDhPubB64,
      'spk':     _spkPubB64,
      'spk_sig': base64Encode(_spkSigBytes!),
      if (_currentOpkId != null) 'opk_id': _currentOpkId,
      if (_opkPubB64 != null) 'opk': _opkPubB64,
    });
  }

  /// Parses a Handshake Payload (v2 or v3) or a raw I2P destination string.
  ///
  /// Returns a map with keys:
  /// - `destination`      — I2P destination key
  /// - `identityPublicKey`— X25519 DH public key (base64), empty if absent
  /// - `preKeyBundle`     — JSON-encoded [PreKeyBundle] if v3, empty if absent
  Map<String, String> parseHandshakePayload(String rawPayload) {
    try {
      final decoded = jsonDecode(rawPayload) as Map<String, dynamic>;
      final dest    = (decoded['dest'] as String? ?? rawPayload).trim();
      final version = decoded['v'] as int? ?? 2;

      if (version >= 3 &&
          decoded.containsKey('ik_ed')   &&
          decoded.containsKey('ik_dh')   &&
          decoded.containsKey('spk')     &&
          decoded.containsKey('spk_sig')) {
        // v3 — full PreKeyBundle embedded (with optional OPK pool)
        final rawOpks = decoded['opks'];
        final bundle = PreKeyBundle(
          ikPubEd: base64Decode(decoded['ik_ed']   as String),
          ikPubDh: base64Decode(decoded['ik_dh']   as String),
          spkPub:  base64Decode(decoded['spk']     as String),
          spkSig:  base64Decode(decoded['spk_sig'] as String),
          opkId:   decoded['opk_id'] as int?,
          opkPub:  decoded['opk'] != null
                   ? base64Decode(decoded['opk'] as String)
                   : null,
          opks: rawOpks is Map
              ? {
                  for (final entry in rawOpks.entries)
                    int.parse(entry.key as String):
                        base64Decode(entry.value as String),
                }
              : const {},
        );
        return {
          'destination':       dest,
          'identityPublicKey': decoded['ik_dh'] as String? ?? '',
          'preKeyBundle':      jsonEncode(bundle.toJson()),
        };
      }

      // v2 — single X25519 DH key
      return {
        'destination':       dest,
        'identityPublicKey': (decoded['id_pub'] as String? ?? '').trim(),
        'preKeyBundle':      '',
      };
    } catch (_) {
      // Plain I2P destination string (legacy QR)
      return {
        'destination':       rawPayload.trim(),
        'identityPublicKey': '',
        'preKeyBundle':      '',
      };
    }
  }

  // ─── Lifecycle: Wipe ─────────────────────────────────────────────────────

  /// Erases all identity keys from secure storage (duress wipe).
  Future<void> clearKeys() async {
    for (final alias in [
      _ikEdPrivAlias, _ikEdPubAlias,
      _ikDhPrivAlias, _ikDhPubAlias,
      _spkPrivAlias,  _spkPubAlias,  _spkSigAlias,
      _opkIdAlias,    _opkPrivAlias, _opkPubAlias,
      _opkRegistryAlias,
    ]) {
      await _secureStorage.delete(key: alias);
    }
    _resetInMemoryState();
  }

  /// Resets all in-memory keys and pool state (for test isolation).
  void resetForTesting() {
    _resetInMemoryState();
  }

  /// Clears all in-memory key material and OPK pool state.
  ///
  /// Shared by [clearKeys] (after secure-storage wipe) and
  /// [resetForTesting] (test isolation). No persistent state is touched.
  void _resetInMemoryState() {
    _ikEdKeyPair  = null;
    _ikDhKeyPair  = null;
    _spkKeyPair   = null;
    _opkStore.clear();
    _opkPubB64ById.clear();
    _consumedOpkIds.clear();
    _currentOpkId = null;
    _spkSigBytes  = null;
    _ikEdPubB64   = null;
    _ikDhPubB64   = null;
    _spkPubB64    = null;
    _opkPubB64    = null;
    _isInitialized = false;
  }
}
