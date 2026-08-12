import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'crypto_service.dart';
import 'identity_key_service.dart';

/// State of an active E2EE ratcheted session between local identity and peer identity.
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
    this.sendCounter = 0,
    this.receiveCounter = 0,
  });

  /// Computes symmetric message key for send ratchet step.
  /// Counter is encoded as 4-byte little-endian to prevent overflow after 255 messages.
  Uint8List getNextSendKey() {
    final c = sendCounter;
    final input = Uint8List.fromList([
      ...sessionKey,
      c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF, (c >> 24) & 0xFF,
    ]);
    sendCounter++;
    return Uint8List.fromList(sha256.convert(input).bytes);
  }

  /// Computes symmetric message key for receive ratchet step.
  /// Returns the key WITHOUT advancing the counter — caller must call commitReceive() on success.
  Uint8List peekReceiveKey() {
    final c = receiveCounter;
    final input = Uint8List.fromList([
      ...sessionKey,
      c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF, (c >> 24) & 0xFF,
    ]);
    return Uint8List.fromList(sha256.convert(input).bytes);
  }

  /// Advances the receive counter after a successful decryption.
  void commitReceive() => receiveCounter++;
}

/// End-to-End Encryption Session Manager for Kamui v2.
class SessionManager {
  static final SessionManager _instance = SessionManager._internal();
  factory SessionManager() => _instance;
  SessionManager._internal();

  final Map<String, SessionState> _sessions = {};
  final _x25519 = X25519();
  final _aesGcm = AesGcm.with256bits();

  /// Retrieves or computes an active E2EE session for a conversation thread.
  Future<SessionState?> getOrCreateSession(
    String conversationId, {
    String? peerIdentityPublicKeyB64,
  }) async {
    if (_sessions.containsKey(conversationId)) {
      return _sessions[conversationId];
    }

    if (peerIdentityPublicKeyB64 == null || peerIdentityPublicKeyB64.isEmpty) {
      return null;
    }

    final identityService = IdentityKeyService();
    if (!identityService.isInitialized) {
      await identityService.init();
    }

    final localKeyPair = identityService.keyPair;
    if (localKeyPair == null) return null;

    try {
      final remotePubBytes = base64Decode(peerIdentityPublicKeyB64);
      final remotePubKey = SimplePublicKey(remotePubBytes, type: KeyPairType.x25519);

      final sharedSecret = await _x25519.sharedSecretKey(
        keyPair: localKeyPair,
        remotePublicKey: remotePubKey,
      );

      final sharedBytes = await sharedSecret.extractBytes();
      final derivedSessionKey = Uint8List.fromList(
        sha256.convert(Uint8List.fromList([...sharedBytes, ...utf8.encode('Kamui-Session-v2')])).bytes,
      );

      final newState = SessionState(
        conversationId: conversationId,
        peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
        sessionKey: derivedSessionKey,
      );

      _sessions[conversationId] = newState;
      return newState;
    } catch (_) {
      return null;
    }
  }

  /// Encrypts plaintext message using the ratcheted conversation session key.
  Future<String> encryptMessage(
    String conversationId,
    String plaintext, {
    String? peerIdentityPublicKeyB64,
  }) async {
    final session = await getOrCreateSession(
      conversationId,
      peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
    );

    if (session != null) {
      try {
        final messageKey = session.getNextSendKey();
        final secretKey = SecretKey(messageKey);
        final nonce = _aesGcm.newNonce();
        final secretBox = await _aesGcm.encrypt(
          utf8.encode(plaintext),
          secretKey: secretKey,
          nonce: nonce,
        );

        final nonceB64 = base64Encode(secretBox.nonce);
        final concatenated = Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
        final ciphertextB64 = base64Encode(concatenated);
        return 'kamui_v2:$nonceB64:$ciphertextB64';
      } catch (_) {
        // Fallback to CryptoService if session encryption fails
      }
    }

    return CryptoService().encrypt(plaintext);
  }

  /// Decrypts encrypted wire payload using session ratchet key or fallback.
  Future<String?> decryptMessage(
    String conversationId,
    String wirePayload, {
    String? peerIdentityPublicKeyB64,
  }) async {
    if (wirePayload.startsWith('kamui_v2:')) {
      // Safe split: prefix is exactly 'kamui_v2:', nonce is next segment,
      // everything after the second ':' is the ciphertext (may contain '=' padding).
      final firstColon  = wirePayload.indexOf(':');          // after 'kamui_v2'
      final secondColon = wirePayload.indexOf(':', firstColon + 1);
      if (firstColon != -1 && secondColon != -1 && secondColon < wirePayload.length - 1) {
        final nonceB64      = wirePayload.substring(firstColon + 1, secondColon);
        final ciphertextB64 = wirePayload.substring(secondColon + 1);

        final session = await getOrCreateSession(
          conversationId,
          peerIdentityPublicKeyB64: peerIdentityPublicKeyB64,
        );

        if (session != null) {
          // Peek the key without advancing counter — only commit on success
          final messageKey = session.peekReceiveKey();
          try {
            final secretKey       = SecretKey(messageKey);
            final nonce           = base64Decode(nonceB64);
            final concatenated    = base64Decode(ciphertextB64);

            const macLength       = 16;
            final cipherTextBytes = concatenated.sublist(0, concatenated.length - macLength);
            final macBytes        = concatenated.sublist(concatenated.length - macLength);

            final secretBox = SecretBox(
              cipherTextBytes,
              nonce: nonce,
              mac: Mac(macBytes),
            );

            final clearBytes = await _aesGcm.decrypt(secretBox, secretKey: secretKey);
            // Decryption succeeded — advance the receive counter
            session.commitReceive();
            return utf8.decode(clearBytes);
          } catch (_) {
            // Counter NOT advanced — no ratchet desync on MAC failure
          }
        }
      }
    }

    // Fallback for legacy payloads
    return CryptoService().decrypt(wirePayload) ?? wirePayload;
  }

  /// Resets all active sessions from memory.
  void reset() {
    _sessions.clear();
  }
}
