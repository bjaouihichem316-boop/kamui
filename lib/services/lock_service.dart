import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:pointycastle/export.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Service managing Biometric Authentication, Security PINs, and Duress Mode.
///
/// ## PIN storage (Phase 3)
/// PINs are never persisted as plaintext. Each PIN is hashed with
/// PBKDF2-HMAC-SHA256 over a 16-byte random salt ([Random.secure]) and stored
/// as:
///
/// ```
/// pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
/// ```
///
/// Secure storage protects the record at rest; hashing protects against
/// storage-dump extraction. Entries written by pre-Phase-3 builds (raw
/// plaintext, no `$`-delimited marker) are transparently upgraded to the
/// hashed format on their first successful verification.
///
/// ## Rate limiting (Phase 6)
/// [verifyPin] is the rate-limited verification entry point used by the lock
/// screen. After [maxConsecutiveFailures] consecutive failed attempts the
/// service enters a lockout window starting at [initialLockout] and doubling
/// with each subsequent lockout, capped at [maxLockout]. A successful unlock
/// resets both the failure counter and the escalation counter. Lockout state
/// (counters + lockout-until timestamp) persists in SharedPreferences — it is
/// not secret data, only throttling metadata. During a lockout NO pin is
/// verified at all (not even against the duress slot), so an attacker cannot
/// learn whether any candidate PIN is the duress PIN: every attempt receives
/// the identical locked-out response.
class LockService {
  static final LockService _instance = LockService._internal();
  factory LockService() => _instance;

  /// Production PBKDF2 round count (~300–500ms unlock budget).
  static const int defaultIterations = 200000;

  /// Marker prefix identifying a hashed PIN entry.
  static const String hashMarker = 'pbkdf2_sha256';

  // ─── Storage keys ─────────────────────────────────────────────────────────
  static const String pinStorageKey       = 'kamui_lock_pin';
  static const String duressPinStorageKey = 'kamui_duress_pin';
  static const String enabledStorageKey   = 'kamui_lock_enabled';

  // ─── Rate-limit storage keys (SharedPreferences — not secret data) ────────
  /// Consecutive failed verification attempts since the last success.
  static const String failedAttemptsKey = 'kamui_lock_failed_attempts';

  /// Epoch-ms timestamp until which verification is locked out.
  static const String lockoutUntilKey = 'kamui_lock_lockout_until_ms';

  /// How many lockouts have fired since the last successful unlock
  /// (drives the doubling escalation window).
  static const String lockoutCountKey = 'kamui_lock_lockout_count';

  // ─── Rate-limit policy ────────────────────────────────────────────────────
  /// Failed attempts tolerated before the first lockout fires.
  static const int maxConsecutiveFailures = 5;

  /// Duration of the first lockout window; doubles per subsequent lockout.
  static const Duration initialLockout = Duration(seconds: 30);

  /// Hard cap for the escalating lockout window.
  static const Duration maxLockout = Duration(minutes: 15);

  static const int _saltLengthBytes = 16;
  static const int _hashLengthBytes = 32; // 256-bit digest

  final LocalAuthentication _localAuth;
  final FlutterSecureStorage _storage;

  /// Injectable clock so tests can fast-forward through lockout windows
  /// without real delays.
  final DateTime Function() _now;

  /// PBKDF2 rounds used when creating NEW hash records. Verification always
  /// honors the round count embedded in the stored record.
  final int _iterations;

  final Random _random = Random.secure();

  LockService._internal({
    FlutterSecureStorage? storage,
    LocalAuthentication? localAuth,
    int iterations = defaultIterations,
    DateTime Function()? clock,
  })  : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
            ),
        _localAuth = localAuth ?? LocalAuthentication(),
        _now = clock ?? DateTime.now,
        _iterations = iterations {
    if (iterations < 1) {
      throw ArgumentError.value(iterations, 'iterations', 'Must be >= 1');
    }
  }

  /// Factory for isolated instances in tests or multi-profile scenarios.
  ///
  /// Defaults to a low iteration count so test suites are not throttled by
  /// PBKDF2; production code must use [LockService.new] (200k rounds).
  factory LockService.isolated({
    FlutterSecureStorage? storage,
    int iterations = 1000,
    DateTime Function()? clock,
  }) {
    return LockService._internal(
      storage: storage,
      iterations: iterations,
      clock: clock,
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BIOMETRICS
  // ═══════════════════════════════════════════════════════════════════════════

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

  // ═══════════════════════════════════════════════════════════════════════════
  // SETUP
  // ═══════════════════════════════════════════════════════════════════════════

  /// Saves the Primary PIN and optional Duress PIN as salted PBKDF2 hashes.
  ///
  /// Args:
  ///   normalPin: Primary unlock PIN (4–6 digits).
  ///   duressPin: Optional panic-wipe PIN; must differ from [normalPin].
  ///
  /// Throws:
  ///   ArgumentError: If either PIN is not 4–6 digits, or both PINs are equal.
  ///     Error messages never contain the PIN values themselves.
  Future<void> setupSecurity({
    required String normalPin,
    String? duressPin,
  }) async {
    _assertValidPin(normalPin, 'normalPin');
    final hasDuress = duressPin != null && duressPin.isNotEmpty;
    if (hasDuress) {
      _assertValidPin(duressPin, 'duressPin');
      if (duressPin == normalPin) {
        throw ArgumentError('Duress PIN must differ from the primary PIN');
      }
    }

    await _storage.write(key: pinStorageKey, value: _hashPin(normalPin));
    if (hasDuress) {
      await _storage.write(key: duressPinStorageKey, value: _hashPin(duressPin));
    }
    await _storage.write(key: enabledStorageKey, value: 'true');
    // Fresh shield arm starts with a clean rate-limit slate.
    await resetRateLimit();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // VERIFICATION
  // ═══════════════════════════════════════════════════════════════════════════

  /// Checks if the entered PIN matches the Primary PIN.
  ///
  /// Legacy plaintext entries are upgraded to the hashed format on success.
  Future<bool> isNormalPin(String pin) async {
    final stored = await _storage.read(key: pinStorageKey);
    return _verifyStored(pin, stored, pinStorageKey);
  }

  /// Checks if the entered PIN triggers **Duress Mode (Panic Wipe)**.
  ///
  /// Legacy plaintext entries are upgraded to the hashed format on success.
  Future<bool> isDuressPin(String pin) async {
    final stored = await _storage.read(key: duressPinStorageKey);
    return _verifyStored(pin, stored, duressPinStorageKey);
  }

  /// Whether app lock is enabled.
  Future<bool> isLockEnabled() async {
    final val = await _storage.read(key: enabledStorageKey);
    return val == 'true';
  }

  /// Disables app lock and erases both PIN records.
  Future<void> disableLock() async {
    await _storage.delete(key: pinStorageKey);
    await _storage.delete(key: duressPinStorageKey);
    await _storage.write(key: enabledStorageKey, value: 'false');
    // A disarmed shield must not inherit stale lockout state.
    await resetRateLimit();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RATE LIMITING (Phase 6)
  // ═══════════════════════════════════════════════════════════════════════════

  /// Rate-limited verification of one lock-screen submission.
  ///
  /// Contract:
  ///   • While locked out, NO pin is verified — not even against the duress
  ///     slot — so the response is identical regardless of what was typed and
  ///     cannot reveal whether a candidate PIN is the duress PIN.
  ///   • A primary-PIN match returns [PinAttemptStatus.primaryUnlocked] and
  ///     resets the failure + escalation counters.
  ///   • A duress-PIN match returns [PinAttemptStatus.duressUnlocked] and also
  ///     resets the counters (the caller performs the panic wipe).
  ///   • Anything else records one failure; reaching
  ///     [maxConsecutiveFailures] starts a lockout window of [initialLockout]
  ///     doubled per prior lockout, capped at [maxLockout].
  Future<PinAttemptResult> verifyPin(String pin) async {
    final remaining = await remainingLockout();
    if (remaining > Duration.zero) {
      return PinAttemptResult.lockedOut(remaining);
    }
    if (await isNormalPin(pin)) {
      await resetRateLimit();
      return const PinAttemptResult.primaryUnlocked();
    }
    if (await isDuressPin(pin)) {
      await resetRateLimit();
      return const PinAttemptResult.duressUnlocked();
    }
    return _recordFailedAttempt();
  }

  /// Remaining lockout time; [Duration.zero] when not locked out.
  Future<Duration> remainingLockout() async {
    final prefs = await SharedPreferences.getInstance();
    final untilMs = prefs.getInt(lockoutUntilKey);
    if (untilMs == null) return Duration.zero;
    final remaining =
        DateTime.fromMillisecondsSinceEpoch(untilMs).difference(_now());
    return remaining.isNegative ? Duration.zero : remaining;
  }

  /// Convenience predicate over [remainingLockout].
  Future<bool> isLockedOut() async =>
      (await remainingLockout()) > Duration.zero;

  /// Clears failure/escalation counters and any pending lockout timestamp.
  Future<void> resetRateLimit() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(failedAttemptsKey, 0);
    await prefs.setInt(lockoutCountKey, 0);
    await prefs.remove(lockoutUntilKey);
  }

  /// Records one failed attempt and arms a lockout when the threshold is hit.
  Future<PinAttemptResult> _recordFailedAttempt() async {
    final prefs = await SharedPreferences.getInstance();
    final failures = (prefs.getInt(failedAttemptsKey) ?? 0) + 1;
    await prefs.setInt(failedAttemptsKey, failures);
    if (failures < maxConsecutiveFailures) {
      return const PinAttemptResult.denied();
    }

    final lockouts = (prefs.getInt(lockoutCountKey) ?? 0) + 1;
    await prefs.setInt(lockoutCountKey, lockouts);

    // initialLockout * 2^(lockouts-1), capped. The exponent clamp keeps the
    // shift in safe integer territory before the cap comparison runs.
    final exponent = min(lockouts - 1, 32);
    var window = initialLockout * (1 << exponent);
    if (window > maxLockout) window = maxLockout;

    final until = _now().add(window);
    await prefs.setInt(lockoutUntilKey, until.millisecondsSinceEpoch);
    return PinAttemptResult.lockedOut(window);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HASHING & COMPARISON PRIMITIVES
  // ═══════════════════════════════════════════════════════════════════════════

  /// Length-safe constant-time equality for fixed-range secrets (PIN digests).
  ///
  /// Returns false immediately on length mismatch — lengths are not secret
  /// for fixed-range PIN hashes. Never short-circuits on content.
  static bool constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Whether [stored] uses the Phase-3 hashed format (`pbkdf2_sha256$…`).
  static bool isHashedEntry(String? stored) =>
      stored != null && stored.startsWith('$hashMarker\$');

  /// Whether [pin] is an acceptable user-chosen PIN (4–6 ASCII digits).
  static bool isValidPin(String pin) => RegExp(r'^[0-9]{4,6}$').hasMatch(pin);

  /// Verifies [pin] against [stored], transparently upgrading legacy
  /// plaintext entries to the hashed format under [storageKey].
  ///
  /// Corrupt/tampered records fail closed without throwing.
  Future<bool> _verifyStored(String pin, String? stored, String storageKey) async {
    if (stored == null || stored.isEmpty) return false;

    // Legacy plaintext entry (pre-Phase-3 install): verify directly, then
    // re-store as a salted hash so plaintext never outlives one unlock.
    if (!stored.contains('\$')) {
      if (!constantTimeEquals(utf8.encode(stored), utf8.encode(pin))) {
        return false;
      }
      await _storage.write(key: storageKey, value: _hashPin(pin));
      return true;
    }

    final record = _parseHashRecord(stored);
    if (record == null) return false;

    final computed = _deriveHash(
      pin,
      salt: record.salt,
      iterations: record.iterations,
    );
    return constantTimeEquals(computed, record.hash);
  }

  /// Derives the PBKDF2-HMAC-SHA256 digest of [pin].
  Uint8List _deriveHash(
    String pin, {
    required Uint8List salt,
    required int iterations,
  }) {
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, iterations, _hashLengthBytes));
    return derivator.process(Uint8List.fromList(utf8.encode(pin)));
  }

  /// Creates a fresh hashed record for [pin] with a random 16-byte salt.
  String _hashPin(String pin) {
    final salt = Uint8List.fromList(
      List<int>.generate(_saltLengthBytes, (_) => _random.nextInt(256)),
    );
    final hash = _deriveHash(pin, salt: salt, iterations: _iterations);
    return [
      hashMarker,
      '$_iterations',
      base64Encode(salt),
      base64Encode(hash),
    ].join('\$');
  }

  /// Parses `marker$iterations$salt_b64$hash_b64`; null if malformed.
  ({int iterations, Uint8List salt, Uint8List hash})? _parseHashRecord(
    String stored,
  ) {
    final parts = stored.split('\$');
    if (parts.length != 4 || parts[0] != hashMarker) return null;
    final iterations = int.tryParse(parts[1]);
    if (iterations == null || iterations < 1) return null;
    try {
      final salt = base64Decode(parts[2]);
      final hash = base64Decode(parts[3]);
      if (salt.isEmpty || hash.isEmpty) return null;
      return (iterations: iterations, salt: salt, hash: hash);
    } on FormatException {
      return null;
    } on ArgumentError {
      return null;
    }
  }

  void _assertValidPin(String pin, String paramName) {
    if (!isValidPin(pin)) {
      // Deliberately does NOT embed the value — never echo PINs.
      throw ArgumentError('$paramName must be 4–6 digits');
    }
  }
}

/// Outcome of one rate-limited lock-screen verification attempt.
enum PinAttemptStatus {
  /// Primary PIN matched — grant access.
  primaryUnlocked,

  /// Duress PIN matched — caller performs the silent panic wipe.
  duressUnlocked,

  /// No slot matched and no lockout is active — generic failure only.
  denied,

  /// Rate limiter active — nothing was verified; identical response
  /// regardless of the submitted value.
  lockedOut,
}

/// Immutable result of [LockService.verifyPin].
class PinAttemptResult {
  const PinAttemptResult.primaryUnlocked()
      : this._(PinAttemptStatus.primaryUnlocked);
  const PinAttemptResult.duressUnlocked()
      : this._(PinAttemptStatus.duressUnlocked);
  const PinAttemptResult.denied() : this._(PinAttemptStatus.denied);

  /// [lockoutRemaining] is the window that was just armed or is still running.
  const PinAttemptResult.lockedOut(Duration lockoutRemaining)
      : this._(PinAttemptStatus.lockedOut, lockoutRemaining);

  const PinAttemptResult._(this.status,
      [this.lockoutRemaining = Duration.zero]);

  final PinAttemptStatus status;

  /// Meaningful when [status] is [PinAttemptStatus.lockedOut]; Duration.zero
  /// otherwise.
  final Duration lockoutRemaining;

  bool get unlocked =>
      status == PinAttemptStatus.primaryUnlocked ||
      status == PinAttemptStatus.duressUnlocked;
}
