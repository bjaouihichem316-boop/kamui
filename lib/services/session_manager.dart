import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'double_ratchet.dart';
import 'identity_key_service.dart';
import 'x3dh_service.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Exceptions
// ══════════════════════════════════════════════════════════════════════════════

/// Thrown when a secure v2/v3/v4 session cannot be established or encryption
/// fails. Callers MUST surface this error and abort the send — no silent
/// downgrade to weaker encryption is permitted.
class SessionUnavailableException implements Exception {
  final String reason;
  const SessionUnavailableException(this.reason);

  @override
  String toString() => 'SessionUnavailableException: $reason';
}

// ══════════════════════════════════════════════════════════════════════════════
// Legacy v2 Session State (backward compatibility only)
// ══════════════════════════════════════════════════════════════════════════════

/// Symmetric-only session state for Kamui v2 peers (no DH ratchet).
/// Retained for backward compatibility with peers that have not upgraded to v4.
class SessionState {
  final String conversationId;
  final String peerIdentityPublicKeyB64;
  final Uint8List sessionKey;
  int sendCounter;
  int receiveCounter;

  SessionState({
    required this.conversationId,
    required this.peerIdentityPublicKeyB64,
    required this.sessionKey,
    this.sendCounter    = 0,
    this.receiveCounter = 0,
  });

  /// Symmetric send ratchet step — derives message key from (sessionKey ‖ counter).
  Uint8List getNextSendKey() {
    final c     = sendCounter;
    final input = Uint8List.fromList([
      ...sessionKey,
      c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF, (c >> 24) & 0xFF,
    ]);
    sendCounter++;
    return Uint8List.fromList(sha256.convert(input).bytes);
  }

  /// Peeks the receive key WITHOUT advancing the counter.
  Uint8List peekReceiveKey() {
    final c     = receiveCounter;
    final input = Uint8List.fromList([
      ...sessionKey,
      c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF, (c >> 24) & 0xFF,
    ]);
    return Uint8List.fromList(sha256.convert(input).bytes);
  }

  /// Advances the receive counter after a successful decryption.
  void commitReceive() => receiveCounter++;
}

// ══════════════════════════════════════════════════════════════════════════════
// Session Manager
// ══════════════════════════════════════════════════════════════════════════════

/// End-to-End Encryption Session Manager for Kamui v2 / v4.
///
/// ## Protocol routing
///
/// | Version | Trigger                       | Encryption                        |
/// |---------|-------------------------------|-----------------------------------|
/// | **v4**  | `peerPreKeyBundleJson` present| X3DH → Double Ratchet (AES-GCM)   |
/// | **v2**  | Only `peerIdentityPublicKeyB64`| Single X25519 DH → Symmetric KDF  |
///
/// ## Fail-Closed guarantee
/// [encryptMessage] ALWAYS throws [SessionUnavailableException] on any error.
/// There is NO silent fallback to plaintext or weaker encryption.
class SessionManager {
  static final SessionManager _instance = SessionManager._internal();
  factory SessionManager() => _instance;

  final IdentityKeyService Function() _getIdentityService;

  SessionManager._internal({IdentityKeyService? identityService})
      : _getIdentityService = identityService != null
            ? (() => identityService)
            : (() => IdentityKeyService());

  /// Factory for isolated instances in tests or multi-identity scenarios.
  factory SessionManager.isolated({IdentityKeyService? identityService}) {
    return SessionManager._internal(identityService: identityService);
  }

  // Active v4 Double Ratchet sessions
  final Map<String, DoubleRatchetSession> _v4Sessions = {};

  // Active v2 legacy sessions (backward compat only)
  final Map<String, SessionState> _v2Sessions = {};

  final _ed25519 = Ed25519();
  final _x25519  = X25519();
  final _aesGcm  = AesGcm.with256bits();

  // ── Session establishment ─────────────────────────────────────────────────

  /// Initiates a v4 Double Ratchet session as Sender (Alice) using [peerPreKeyBundleJson].
  Future<DoubleRatchetSession> initiateSessionV4(
    String conversationId, {
    required String peerPreKeyBundleJson,
  }) async {
    final session = await getOrCreateV4Session(
      conversationId,
      peerPreKeyBundleJson: peerPreKeyBundleJson,
    );
    if (session == null) {
      throw const SessionUnavailableException(
        'Failed to initiate v4 Double Ratchet session — check PreKeyBundle.',
      );
    }
    return session;
  }

  /// Accepts / establishes a v4 Double Ratchet session as Receiver (Bob).
  Future<DoubleRatchetSession> acceptSessionV4(
    String conversationId, {
    required String peerIdentityPublicKeyB64,
    required Uint8List sharedSecret,
  }) async {
    if (_v4Sessions.containsKey(conversationId)) {
      return _v4Sessions[conversationId]!;
    }

    final identityService = _getIdentityService();
    if (!identityService.isInitialized) {
      await identityService.init();
    }

    final spkKp = identityService.spkKeyPair;
    if (spkKp == null) {
      throw const SessionUnavailableException(
        'Local SPK keypair not initialized — cannot accept v4 session.',
      );
    }

    final session = await DoubleRatchetSession.initBob(
      conversationId:           conversationId,
      peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
      sk:                       sharedSecret,
      spkBDh:                   spkKp,
    );

    _v4Sessions[conversationId] = session;
    return session;
  }

  /// Retrieves or establishes a **v4 Double Ratchet** session for [conversationId].
  ///
  /// Requires [peerPreKeyBundleJson] (v3 JSON from [IdentityKeyService.parseHandshakePayload]).
  /// Returns the [DoubleRatchetSession], or `null` if keys are unavailable.
  Future<DoubleRatchetSession?> getOrCreateV4Session(
    String conversationId, {
    required String peerPreKeyBundleJson,
  }) async {
    if (_v4Sessions.containsKey(conversationId)) {
      return _v4Sessions[conversationId];
    }

    final identityService = _getIdentityService();
    if (!identityService.isInitialized) {
      await identityService.init();
    }

    return _establishV4Session(conversationId, peerPreKeyBundleJson, identityService);
  }

  /// Retrieves or establishes a **v2 legacy** session for [conversationId].
  Future<SessionState?> getOrCreateSession(
    String conversationId, {
    String? peerIdentityPublicKeyB64,
    String? peerPreKeyBundleJson,
  }) async {
    // Prefer v2 legacy path when no bundle provided
    if (_v2Sessions.containsKey(conversationId)) {
      return _v2Sessions[conversationId];
    }

    if (peerIdentityPublicKeyB64 == null || peerIdentityPublicKeyB64.isEmpty) {
      return null;
    }

    final identityService = _getIdentityService();
    if (!identityService.isInitialized) {
      await identityService.init();
    }

    return _establishV2Session(conversationId, peerIdentityPublicKeyB64, identityService);
  }

  // ── Encryption ────────────────────────────────────────────────────────────

  /// Encrypts [plaintext] using the **v4 Double Ratchet**.
  ///
  /// If no session exists for [conversationId], performs X3DH handshake as Alice,
  /// initializes the ratchet session, encrypts the first message, and wraps
  /// the result in a [HandshakeInitEnvelope] JSON string with Ed25519 identity binding.
  ///
  /// If a session is already active, returns `"kamui_v4:<headerB64>:<nonceB64>:<ciphertextB64>"`.
  ///
  /// **Fail-Closed**: throws [SessionUnavailableException] on any failure.
  Future<String> encryptV4(
    String conversationId,
    String plaintext, {
    String? peerPreKeyBundleJson,
  }) async {
    final identityService = _getIdentityService();
    if (!identityService.isInitialized) {
      await identityService.init();
    }

    // 1. If session already exists, encrypt normally
    if (_v4Sessions.containsKey(conversationId)) {
      final session = _v4Sessions[conversationId]!;
      try {
        return await session.encrypt(plaintext);
      } on RatchetException catch (e) {
        throw SessionUnavailableException('v4 encryption failed: ${e.reason}');
      }
    }

    // 2. First message of conversation — build HandshakeInitEnvelope
    if (peerPreKeyBundleJson == null || peerPreKeyBundleJson.isEmpty) {
      throw const SessionUnavailableException(
        'No v4 Double Ratchet session — peer PreKeyBundle required to establish session.',
      );
    }

    final ikADh = identityService.ikDhKeyPair;
    final ikAEd = identityService.ikEdKeyPair;
    if (ikADh == null ||
        ikAEd == null ||
        identityService.identityEdPublicKeyB64 == null ||
        identityService.identityDhPublicKeyB64 == null) {
      throw const SessionUnavailableException(
        'Local identity keys not initialized — cannot perform X3DH handshake.',
      );
    }

    try {
      final bundleMap = jsonDecode(peerPreKeyBundleJson) as Map<String, dynamic>;
      final bundle    = PreKeyBundle.fromJson(bundleMap);

      // Perform X3DH initiator handshake
      final x3dhResult = await X3dhService.initiatorHandshake(
        ikADh:   ikADh,
        bundleB: bundle,
      );

      // Initialize Double Ratchet session as Alice (initiator)
      final session = await DoubleRatchetSession.initAlice(
        conversationId:           conversationId,
        peerIdentityPublicKeyB64: base64Encode(bundle.ikPubDh),
        sk:                       x3dhResult.sharedSecret,
        bobSpkPub:                bundle.spkPub,
      );

      _v4Sessions[conversationId] = session;

      // Encrypt the first message with the new ratchet session
      final firstMessage = await session.encrypt(plaintext);

      // Cryptographically bind IK_ed and IK_dh with Ed25519 signature
      final ikEdBytes  = base64Decode(identityService.identityEdPublicKeyB64!);
      final ikDhBytes  = base64Decode(identityService.identityDhPublicKeyB64!);
      final transcript = X3dhService.computeIdentityBindingTranscript(ikEdBytes, ikDhBytes);
      final sig        = await _ed25519.sign(transcript, keyPair: ikAEd);

      // Wrap in HandshakeInitEnvelope
      final envelope = HandshakeInitEnvelope(
        ikEd:         ikEdBytes,
        ikDh:         ikDhBytes,
        ikSig:        sig.bytes,
        ek:           x3dhResult.ekPub,
        opkIdUsed:    x3dhResult.opkId,
        firstMessage: firstMessage,
      );

      return jsonEncode(envelope.toJson());
    } on X3dhException catch (e) {
      throw SessionUnavailableException('X3DH initiator handshake failed: ${e.reason}');
    } on RatchetException catch (e) {
      throw SessionUnavailableException('Double Ratchet initialization failed: ${e.reason}');
    } catch (e) {
      throw SessionUnavailableException('v4 handshake init failed for $conversationId: $e');
    }
  }

  /// Decrypts a v4 payload (either [HandshakeInitEnvelope] JSON or `"kamui_v4:..."`).
  ///
  /// Returns the plaintext or throws [SessionUnavailableException].
  Future<String> decryptV4(
    String conversationId,
    String wirePayload, {
    String? peerPreKeyBundleJson,
  }) async {
    final identityService = _getIdentityService();
    if (!identityService.isInitialized) {
      await identityService.init();
    }

    // 1. Check if wirePayload is a HandshakeInitEnvelope
    if (HandshakeInitEnvelope.isHandshakeEnvelope(wirePayload)) {
      try {
        final decodedMap = jsonDecode(wirePayload.trim()) as Map<String, dynamic>;
        final envelope   = HandshakeInitEnvelope.fromJson(decodedMap);

        // Verify Alice's Identity Key binding: IK_ed must authenticate IK_dh
        final isValidBinding = await X3dhService.verifyIdentityBinding(
          ikEd:  envelope.ikEd,
          ikDh:  envelope.ikDh,
          ikSig: envelope.ikSig,
        );
        if (!isValidBinding) {
          throw const SessionUnavailableException(
            'Identity binding verification failed: IK_ed does not cryptographically authenticate IK_dh.',
          );
        }

        final ikBDh = identityService.ikDhKeyPair;
        final spkB  = identityService.spkKeyPair;
        if (ikBDh == null || spkB == null) {
          throw const SessionUnavailableException(
            'Local identity keys (IK_dh, SPK) not initialized for receiver handshake.',
          );
        }

        // Look up OPK if used (fails closed on replay or invalid OPK ID)
        SimpleKeyPair? opkB;
        if (envelope.opkIdUsed != null) {
          try {
            opkB = identityService.getOpk(envelope.opkIdUsed!);
          } on X3dhException catch (e) {
            throw SessionUnavailableException('OPK validation failed (replay or invalid): ${e.reason}');
          }
        }

        // Derive shared secret as Bob
        final sharedSecret = await X3dhService.responderHandshake(
          ikBDh:    ikBDh,
          spkB:     spkB,
          opkB:     opkB,
          ekAPub:   envelope.ek,
          ikADhPub: envelope.ikDh,
        );

        // Initialize candidate Double Ratchet session as Bob (receiver)
        final candidateBobSession = await DoubleRatchetSession.initBob(
          conversationId:           conversationId,
          peerIdentityPublicKeyB64: base64Encode(envelope.ikDh),
          sk:                       sharedSecret,
          spkBDh:                   spkB,
        );

        // Decrypt first_message on candidate session — validates AEAD MAC
        final plaintext = await candidateBobSession.decrypt(envelope.firstMessage);

        // Transactional commit: Consume OPK and commit session ONLY after successful AEAD auth
        if (envelope.opkIdUsed != null) {
          await identityService.consumeOpk(envelope.opkIdUsed!);
        }
        _v4Sessions[conversationId] = candidateBobSession;

        return plaintext;
      } on SessionUnavailableException {
        rethrow;
      } on X3dhException catch (e) {
        throw SessionUnavailableException('X3DH responder handshake failed: ${e.reason}');
      } on RatchetException catch (e) {
        throw SessionUnavailableException('Double Ratchet decryption failed: ${e.reason}');
      } catch (e) {
        throw SessionUnavailableException('Handshake envelope processing failed: $e');
      }
    }

    // 2. Normal established session message ("kamui_v4:...")
    DoubleRatchetSession? session = _v4Sessions[conversationId];
    if (session == null && peerPreKeyBundleJson != null && peerPreKeyBundleJson.isNotEmpty) {
      session = await getOrCreateV4Session(
        conversationId,
        peerPreKeyBundleJson: peerPreKeyBundleJson,
      );
    }

    if (session == null) {
      throw const SessionUnavailableException(
        'No v4 Double Ratchet session available for decryption.',
      );
    }

    try {
      return await session.decrypt(wirePayload);
    } on RatchetException catch (e) {
      throw SessionUnavailableException('v4 decryption failed: ${e.reason}');
    }
  }

  /// Encrypts [plaintext] using the legacy **v2 symmetric** session.
  ///
  /// Wire format: `"kamui_v2:<nonceB64>:<ciphertextB64>"`
  ///
  /// **Fail-Closed**: throws [SessionUnavailableException] on any failure.
  Future<String> encryptMessage(
    String conversationId,
    String plaintext, {
    String? peerIdentityPublicKeyB64,
    String? peerPreKeyBundleJson,
  }) async {
    final session = await getOrCreateSession(
      conversationId,
      peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
      peerPreKeyBundleJson:     peerPreKeyBundleJson,
    );

    if (session == null) {
      throw const SessionUnavailableException(
        'No active v2 session — peer identity key required to establish E2EE.',
      );
    }

    try {
      final messageKey = session.getNextSendKey();
      final secretKey  = SecretKey(messageKey);
      final nonce      = _aesGcm.newNonce();
      final secretBox  = await _aesGcm.encrypt(
        utf8.encode(plaintext),
        secretKey: secretKey,
        nonce:     nonce,
      );

      final nonceB64      = base64Encode(secretBox.nonce);
      final concatenated  = Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
      final ciphertextB64 = base64Encode(concatenated);
      return 'kamui_v2:$nonceB64:$ciphertextB64';
    } catch (e) {
      throw SessionUnavailableException(
        'AES-GCM encryption failed for conversation $conversationId: $e',
      );
    }
  }

  /// Decrypts a `"kamui_v2:..."` payload using the legacy **v2 symmetric** session.
  Future<String?> decryptMessage(
    String conversationId,
    String wirePayload, {
    String? peerIdentityPublicKeyB64,
    String? peerPreKeyBundleJson,
  }) async {
    if (wirePayload.startsWith('kamui_v2:')) {
      final firstColon  = wirePayload.indexOf(':');
      final secondColon = wirePayload.indexOf(':', firstColon + 1);
      if (firstColon  != -1 &&
          secondColon != -1 &&
          secondColon < wirePayload.length - 1) {
        final nonceB64      = wirePayload.substring(firstColon + 1, secondColon);
        final ciphertextB64 = wirePayload.substring(secondColon + 1);

        final session = await getOrCreateSession(
          conversationId,
          peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
          peerPreKeyBundleJson:     peerPreKeyBundleJson,
        );

        if (session != null) {
          final messageKey = session.peekReceiveKey();
          try {
            final secretKey       = SecretKey(messageKey);
            final nonce           = base64Decode(nonceB64);
            final concatenated    = base64Decode(ciphertextB64);
            const macLength       = 16;
            final cipherTextBytes = concatenated.sublist(0, concatenated.length - macLength);
            final macBytes        = concatenated.sublist(concatenated.length - macLength);
            final secretBox       = SecretBox(
              cipherTextBytes,
              nonce: nonce,
              mac:   Mac(macBytes),
            );
            final clearBytes = await _aesGcm.decrypt(secretBox, secretKey: secretKey);
            session.commitReceive();
            return utf8.decode(clearBytes);
          } catch (_) {
            // MAC failure — counter NOT advanced, no ratchet desync
          }
        }
      }
    }
    // Legacy / unknown payload — callers display "message encrypted with older protocol"
    return null;
  }

  /// Resets all active sessions (use during duress wipe / key rotation).
  void reset() {
    _v4Sessions.clear();
    _v2Sessions.clear();
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  /// Establishes a v4 Double Ratchet session via X3DH → DoubleRatchetSession.initAlice.
  Future<DoubleRatchetSession?> _establishV4Session(
    String             conversationId,
    String             peerPreKeyBundleJson,
    IdentityKeyService identityService,
  ) async {
    final ikADh = identityService.ikDhKeyPair;
    if (ikADh == null) {
      throw const SessionUnavailableException(
        'Local X25519 DH identity key not initialized — cannot perform X3DH.',
      );
    }

    try {
      final bundleMap = jsonDecode(peerPreKeyBundleJson) as Map<String, dynamic>;
      final bundle    = PreKeyBundle.fromJson(bundleMap);

      // X3DH handshake — SPK signature verified internally; throws on failure
      final x3dhResult = await X3dhService.initiatorHandshake(
        ikADh:   ikADh,
        bundleB: bundle,
      );

      // Initialise Double Ratchet as Alice (initiator)
      final session = await DoubleRatchetSession.initAlice(
        conversationId:           conversationId,
        peerIdentityPublicKeyB64: base64Encode(bundle.ikPubDh),
        sk:         x3dhResult.sharedSecret,
        bobSpkPub:  bundle.spkPub,
      );

      _v4Sessions[conversationId] = session;
      return session;
    } on X3dhException catch (e) {
      throw SessionUnavailableException('X3DH handshake failed: ${e.reason}');
    } on RatchetException catch (e) {
      throw SessionUnavailableException('Double Ratchet init failed: ${e.reason}');
    } catch (e) {
      throw SessionUnavailableException(
        'v4 session setup failed for $conversationId: $e',
      );
    }
  }

  /// Establishes a v2 legacy session (single X25519 DH + SHA-256 KDF).
  Future<SessionState?> _establishV2Session(
    String             conversationId,
    String             peerIdentityPublicKeyB64,
    IdentityKeyService identityService,
  ) async {
    final localKeyPair = identityService.keyPair;
    if (localKeyPair == null) return null;

    try {
      final remotePubBytes = base64Decode(peerIdentityPublicKeyB64);
      final remotePubKey   = SimplePublicKey(remotePubBytes, type: KeyPairType.x25519);
      final sharedSecret   = await _x25519.sharedSecretKey(
        keyPair:         localKeyPair,
        remotePublicKey: remotePubKey,
      );
      final sharedBytes    = await sharedSecret.extractBytes();
      final derivedKey     = Uint8List.fromList(
        sha256.convert(Uint8List.fromList(
          [...sharedBytes, ...utf8.encode('Kamui-Session-v2')],
        )).bytes,
      );

      final newState = SessionState(
        conversationId:           conversationId,
        peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
        sessionKey:               derivedKey,
      );
      _v2Sessions[conversationId] = newState;
      return newState;
    } catch (e) {
      throw SessionUnavailableException(
        'Key agreement failed for conversation $conversationId: $e',
      );
    }
  }
}
