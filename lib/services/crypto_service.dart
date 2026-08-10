import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';

/// AES-256-GCM symmetric encryption service.
///
/// ### Key lifecycle
/// 1. On first run, a 32-byte random key is generated.
/// 2. The key is stored in the platform Keychain / Keystore via
///    [FlutterSecureStorage] — never persisted in plaintext.
/// 3. Every [encrypt] call generates a fresh 12-byte nonce (IV).
///    The ciphertext is returned as   `nonce_b64:ciphertext_b64`.
///
/// ### Wire format
/// ```
/// base64(nonce_12bytes) : base64(aesgcm_ciphertext)
/// ```
///
/// Phase 3 upgrade path: swap out with a full X3DH / Double Ratchet
/// implementation by replacing [encrypt] / [decrypt] in this class only.
class CryptoService {
  // ─── Singleton ───────────────────────────────────────────────────────────
  static final CryptoService _instance = CryptoService._internal();
  factory CryptoService() => _instance;
  CryptoService._internal();

  // ─── Config ──────────────────────────────────────────────────────────────
  static const _keyAlias    = 'kamui_aes256_key';
  static const _keyLength   = 32; // 256 bits
  static const _nonceLength = 12; // 96 bits — GCM standard
  static const _tagLength   = 16; // 128-bit authentication tag

  final _secureStorage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  Uint8List? _cachedKey;

  // ═══════════════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ═══════════════════════════════════════════════════════════════════════════

  /// Initializes the key: loads from secure storage or generates a new one.
  Future<void> init() async {
    final existing = await _secureStorage.read(key: _keyAlias);
    if (existing != null) {
      _cachedKey = base64Decode(existing);
    } else {
      _cachedKey = _generateKey();
      await _secureStorage.write(
        key: _keyAlias,
        value: base64Encode(_cachedKey!),
      );
    }
  }

  /// Encrypts [plaintext] with AES-256-GCM.
  /// Returns `"nonce_b64:ciphertext_b64"` or throws if key not initialized.
  String encrypt(String plaintext) {
    _assertReady();
    final key   = _cachedKey!;
    final nonce = _generateNonce();
    final pt    = utf8.encode(plaintext);

    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        true,
        AEADParameters(KeyParameter(key), _tagLength * 8, nonce, Uint8List(0)),
      );

    final output   = Uint8List(cipher.getOutputSize(pt.length));
    var offset = 0;
    offset += cipher.processBytes(pt, 0, pt.length, output, offset);
    cipher.doFinal(output, offset);

    return '${base64Encode(nonce)}:${base64Encode(output)}';
  }

  /// Decrypts a value produced by [encrypt].
  /// Returns the plaintext string, or `null` if decryption fails.
  String? decrypt(String encryptedValue) {
    _assertReady();
    try {
      final parts = encryptedValue.split(':');
      if (parts.length != 2) return null;

      final nonce  = base64Decode(parts[0]);
      final ct     = base64Decode(parts[1]);
      final key    = _cachedKey!;

      final cipher = GCMBlockCipher(AESEngine())
        ..init(
          false,
          AEADParameters(KeyParameter(key), _tagLength * 8, nonce, Uint8List(0)),
        );

      final output = Uint8List(cipher.getOutputSize(ct.length));
      var offset   = 0;
      offset += cipher.processBytes(ct, 0, ct.length, output, offset);
      cipher.doFinal(output, offset);

      return utf8.decode(output.sublist(0, output.length));
    } catch (_) {
      return null;
    }
  }

  /// Whether the service has been initialized with a key.
  bool get isReady => _cachedKey != null;

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL
  // ═══════════════════════════════════════════════════════════════════════════

  Uint8List _generateKey() {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(_keyLength, (_) => rng.nextInt(256)));
  }

  Uint8List _generateNonce() {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(_nonceLength, (_) => rng.nextInt(256)));
  }

  void _assertReady() {
    if (_cachedKey == null) {
      throw StateError('CryptoService not initialized — call await init() first.');
    }
  }
}
