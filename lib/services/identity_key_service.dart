import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Service for managing independent X25519 cryptographic Identity KeyPairs.
class IdentityKeyService {
  static final IdentityKeyService _instance = IdentityKeyService._internal();
  factory IdentityKeyService() => _instance;
  IdentityKeyService._internal();

  static const _privKeyAlias = 'kamui_identity_x25519_priv';
  static const _pubKeyAlias  = 'kamui_identity_x25519_pub';

  final _secureStorage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  final _algorithm = X25519();
  SimpleKeyPair? _keyPair;
  String? _publicKeyB64;

  bool _isInitialized = false;
  bool get isInitialized => _isInitialized;

  String? get identityPublicKeyB64 => _publicKeyB64;
  SimpleKeyPair? get keyPair => _keyPair;

  /// Initializes or generates the X25519 Identity KeyPair.
  Future<void> init() async {
    if (_isInitialized) return;

    final existingPrivB64 = await _secureStorage.read(key: _privKeyAlias);
    final existingPubB64  = await _secureStorage.read(key: _pubKeyAlias);

    if (existingPrivB64 != null && existingPubB64 != null) {
      final privBytes = base64Decode(existingPrivB64);
      final pubBytes  = base64Decode(existingPubB64);

      _publicKeyB64 = existingPubB64;
      _keyPair = SimpleKeyPairData(
        privBytes,
        publicKey: SimplePublicKey(pubBytes, type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );
    } else {
      await generateNewIdentityKeyPair();
    }

    _isInitialized = true;
  }

  /// Generates a fresh X25519 Identity KeyPair and stores it securely.
  Future<void> generateNewIdentityKeyPair() async {
    final keyPair = await _algorithm.newKeyPair();
    final pubKey = await keyPair.extractPublicKey();
    final privBytes = await keyPair.extractPrivateKeyBytes();

    _keyPair = keyPair;
    _publicKeyB64 = base64Encode(pubKey.bytes);

    await _secureStorage.write(key: _privKeyAlias, value: base64Encode(privBytes));
    await _secureStorage.write(key: _pubKeyAlias,  value: _publicKeyB64!);
  }

  /// Clears stored identity keys from secure storage.
  Future<void> clearKeys() async {
    await _secureStorage.delete(key: _privKeyAlias);
    await _secureStorage.delete(key: _pubKeyAlias);
    _keyPair = null;
    _publicKeyB64 = null;
    _isInitialized = false;
  }

  /// Encodes a JSON Handshake Payload combining Destination Key and X25519 Identity Public Key.
  String generateHandshakePayload(String destinationKey) {
    final payloadMap = {
      'v': 2,
      'dest': destinationKey,
      'id_pub': _publicKeyB64 ?? '',
    };
    return jsonEncode(payloadMap);
  }

  /// Parses a Handshake Payload or QR data string.
  Map<String, String> parseHandshakePayload(String rawPayload) {
    try {
      final decoded = jsonDecode(rawPayload) as Map<String, dynamic>;
      return {
        'destination': (decoded['dest'] as String? ?? rawPayload).trim(),
        'identityPublicKey': (decoded['id_pub'] as String? ?? '').trim(),
      };
    } catch (_) {
      // Fallback if plain destination string was scanned
      return {
        'destination': rawPayload.trim(),
        'identityPublicKey': '',
      };
    }
  }
}
