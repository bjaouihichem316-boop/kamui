import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

/// Service managing Biometric Authentication, Security PINs, and Duress Mode.
class LockService {
  static final LockService _instance = LockService._internal();
  factory LockService() => _instance;
  LockService._internal();

  final LocalAuthentication _localAuth = LocalAuthentication();
  final FlutterSecureStorage _storage  = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  static const _pinKey       = 'kamui_lock_pin';
  static const _duressPinKey = 'kamui_duress_pin';
  static const _enabledKey   = 'kamui_lock_enabled';

  /// Whether biometric hardware or device credential is available.
  Future<bool> canAuthenticate() async {
    try {
      final isSupported = await _localAuth.isDeviceSupported();
      final canCheck    = await _localAuth.canCheckBiometrics;
      return isSupported || canCheck;
    } catch (_) {
      return false;
    }
  }

  /// Triggers native FaceID / TouchID / Fingerprint prompt.
  Future<bool> authenticateBiometrics() async {
    try {
      return await _localAuth.authenticate(
        localizedReason: 'Authenticate to access Kamui Secure Dimension',
        options: const AuthenticationOptions(
          stickyAuth:           true,
          biometricOnly:        false,
          useErrorDialogs:      true,
        ),
      );
    } catch (_) {
      return false;
    }
  }

  /// Saves the Primary PIN and optional Duress PIN.
  Future<void> setupSecurity({
    required String normalPin,
    String? duressPin,
  }) async {
    await _storage.write(key: _pinKey, value: normalPin);
    if (duressPin != null && duressPin.isNotEmpty) {
      await _storage.write(key: _duressPinKey, value: duressPin);
    }
    await _storage.write(key: _enabledKey, value: 'true');
  }

  /// Checks if the entered PIN matches the Primary PIN.
  Future<bool> isNormalPin(String pin) async {
    final stored = await _storage.read(key: _pinKey);
    return stored != null && stored == pin;
  }

  /// Checks if the entered PIN triggers **Duress Mode (Panic Wipe)**.
  Future<bool> isDuressPin(String pin) async {
    final stored = await _storage.read(key: _duressPinKey);
    return stored != null && stored == pin;
  }

  /// Whether app lock is enabled.
  Future<bool> isLockEnabled() async {
    final val = await _storage.read(key: _enabledKey);
    return val == 'true';
  }

  /// Disables app lock.
  Future<void> disableLock() async {
    await _storage.delete(key: _pinKey);
    await _storage.delete(key: _duressPinKey);
    await _storage.write(key: _enabledKey, value: 'false');
  }
}
