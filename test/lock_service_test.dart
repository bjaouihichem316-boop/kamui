// ignore_for_file: avoid_print
//
// ══════════════════════════════════════════════════════════════════════════════
// Kamui Phase 3 — Lock Screen Reality Test Suite
//
// Covers:
//   1. Correct PIN passes, wrong PIN fails
//   2. Same PIN set twice → different stored hashes (unique salts)
//   3. Legacy plaintext entry auto-upgrades to hashed format on verify
//   4. Duress ≠ primary enforced at setup validation level
//   5. Constant-time helper: equal / different content / length mismatch
//   6. Hash format round-trip + tampered stored hash → false, no crash
//   7. isLockEnabled reflects setup state
//
// Isolation follows the repo pattern: FlutterSecureStorage.setMockInitialValues
// + LockService.isolated (mirrors IdentityKeyService.isolated). PBKDF2 rounds
// are injected low for speed; the production default stays at 200k.
// ══════════════════════════════════════════════════════════════════════════════

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/lock_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const storage = FlutterSecureStorage();

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    // Rate-limit state (Phase 6) persists in SharedPreferences; mock it so
    // setupSecurity/disableLock resets work headlessly.
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();
    await prefs.clear();
  });

  /// Low-round isolated service — keeps the suite fast without weakening
  /// production defaults ([LockService.defaultIterations] stays 200k).
  LockService service() => LockService.isolated(iterations: 1000);

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 1 — Correct PIN passes, wrong fails
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 3.1 — PIN verification', () {
    test('correct PIN passes, wrong PIN fails', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');

      expect(await lock.isNormalPin('482913'), isTrue);
      expect(await lock.isNormalPin('482912'), isFalse);
      expect(await lock.isNormalPin('0482913'), isFalse);
    });

    test('duress verifies only against duress slot and vice versa', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '123456', duressPin: '654321');

      expect(await lock.isDuressPin('654321'), isTrue);
      expect(await lock.isDuressPin('123456'), isFalse);
      expect(await lock.isNormalPin('654321'), isFalse);
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 2 — Unique salts per setup
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 3.1 — Salting', () {
    test('same PIN set twice → different stored hash strings', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '123456');
      final first = await storage.read(key: LockService.pinStorageKey);

      await lock.setupSecurity(normalPin: '123456');
      final second = await storage.read(key: LockService.pinStorageKey);

      expect(first, isNotNull);
      expect(second, isNotNull);
      expect(first, isNot(equals(second)),
          reason: 'Random 16-byte salts must make every stored record unique');

      // Both records must still verify against the same PIN.
      expect(await lock.isNormalPin('123456'), isTrue);
    });

    test('primary and duress records are independently salted', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '111222', duressPin: '333444');

      final primary = await storage.read(key: LockService.pinStorageKey);
      final duress  = await storage.read(key: LockService.duressPinStorageKey);
      expect(primary, isNot(equals(duress)));
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 3 — Legacy plaintext migration
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 3.1 — Legacy plaintext upgrade-on-unlock', () {
    test('successful legacy verify upgrades to hashed format', () async {
      FlutterSecureStorage.setMockInitialValues({
        LockService.pinStorageKey: '1337',
        LockService.enabledStorageKey: 'true',
      });
      final lock = service();

      expect(LockService.isHashedEntry('1337'), isFalse);

      expect(await lock.isNormalPin('1337'), isTrue);

      final upgraded = await storage.read(key: LockService.pinStorageKey);
      expect(upgraded, isNotNull);
      expect(LockService.isHashedEntry(upgraded), isTrue,
          reason: 'Plaintext must be replaced by pbkdf2_sha256 record');
      expect(upgraded!.startsWith('${LockService.hashMarker}\$'), isTrue);

      // Post-upgrade behavior is fully hashed.
      expect(await lock.isNormalPin('1337'), isTrue);
      expect(await lock.isNormalPin('7331'), isFalse);
    });

    test('failed legacy verify leaves plaintext untouched', () async {
      FlutterSecureStorage.setMockInitialValues({
        LockService.pinStorageKey: '1337',
      });
      final lock = service();

      expect(await lock.isNormalPin('9999'), isFalse);

      final stored = await storage.read(key: LockService.pinStorageKey);
      expect(stored, equals('1337'),
          reason: 'No rewrite unless verification succeeded');
    });

    test('legacy duress entry upgrades via isDuressPin too', () async {
      FlutterSecureStorage.setMockInitialValues({
        LockService.duressPinStorageKey: '2468',
      });
      final lock = service();

      expect(await lock.isDuressPin('2468'), isTrue);
      final upgraded =
          await storage.read(key: LockService.duressPinStorageKey);
      expect(LockService.isHashedEntry(upgraded), isTrue);
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 4 — Setup validation
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 3.1 — Setup validation', () {
    test('duress == primary rejected at setup level', () async {
      final lock = service();
      await expectLater(
        lock.setupSecurity(normalPin: '1234', duressPin: '1234'),
        throwsArgumentError,
      );

      // Nothing was persisted by the failed setup.
      expect(await storage.read(key: LockService.pinStorageKey), isNull);
      expect(await lock.isLockEnabled(), isFalse);
    });

    test('distinct duress accepted and hashed', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '1234', duressPin: '9876');

      expect(await lock.isNormalPin('9876'), isFalse);
      expect(await lock.isDuressPin('9876'), isTrue);
    });

    test('malformed PINs rejected (length / non-digits)', () async {
      final lock = service();
      await expectLater(lock.setupSecurity(normalPin: '123'),
          throwsArgumentError);
      await expectLater(lock.setupSecurity(normalPin: '1234567'),
          throwsArgumentError);
      await expectLater(
          lock.setupSecurity(normalPin: '12a4'), throwsArgumentError);
      await expectLater(lock.setupSecurity(normalPin: ''), throwsArgumentError);
    });

    test('validation errors never embed the PIN value', () async {
      final lock = service();
      try {
        await lock.setupSecurity(normalPin: '123');
        fail('Expected ArgumentError');
      } on ArgumentError catch (e) {
        expect(e.toString(), isNot(contains('123')),
            reason: 'PINs must never be echoed in error messages');
      }
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 5 — Constant-time comparison helper
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 3.2 — constantTimeEquals', () {
    test('equal content → true', () {
      expect(LockService.constantTimeEquals([1, 2, 3], [1, 2, 3]), isTrue);
      expect(LockService.constantTimeEquals(<int>[], <int>[]), isTrue);
      expect(
        LockService.constantTimeEquals(utf8.encode('abc'), utf8.encode('abc')),
        isTrue,
      );
    });

    test('different content (same length) → false', () {
      expect(LockService.constantTimeEquals([1, 2, 3], [1, 2, 4]), isFalse);
      expect(LockService.constantTimeEquals([0], [1]), isFalse);
    });

    test('length mismatch → false immediately', () {
      expect(LockService.constantTimeEquals([1, 2], [1, 2, 3]), isFalse);
      expect(LockService.constantTimeEquals([1, 2, 3], [1, 2]), isFalse);
      expect(
        LockService.constantTimeEquals(utf8.encode('abc'), utf8.encode('abcd')),
        isFalse,
      );
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 6 — Hash format round-trip & tamper resistance
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 3.1 — Hash format round-trip', () {
    test('store → verify → true; format is marker\$iter\$salt\$hash',
        () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '555555', duressPin: '111111');

      final stored =
          (await storage.read(key: LockService.pinStorageKey))!;
      final parts = stored.split('\$');
      expect(parts, hasLength(4));
      expect(parts[0], equals('pbkdf2_sha256'));
      expect(int.parse(parts[1]), greaterThanOrEqualTo(1));
      expect(base64Decode(parts[2]), hasLength(16),
          reason: 'Salt must be 16 random bytes');
      expect(base64Decode(parts[3]), hasLength(32),
          reason: 'Digest must be 256-bit');

      expect(await lock.isNormalPin('555555'), isTrue);
      expect(await lock.isDuressPin('111111'), isTrue);
    });

    test('injectable iteration count recorded in stored format', () async {
      final lock = LockService.isolated(iterations: 777);
      await lock.setupSecurity(normalPin: '909090');

      final parts =
          (await storage.read(key: LockService.pinStorageKey))!.split('\$');
      expect(parts[1], equals('777'));
      expect(await lock.isNormalPin('909090'), isTrue);
    });

    test('production default iteration count stays at 200k', () {
      expect(LockService.defaultIterations, equals(200000));
    });

    test('tampered digest → false, no crash', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '246810');
      final original =
          (await storage.read(key: LockService.pinStorageKey))!;
      final parts = original.split('\$');

      final tamperedDigest =
          parts[3] == 'AAAA' ? 'BBBB' : 'AAAA';
      FlutterSecureStorage.setMockInitialValues({
        LockService.pinStorageKey:
            [parts[0], parts[1], parts[2], tamperedDigest].join('\$'),
      });
      expect(await lock.isNormalPin('246810'), isFalse);
    });

    test('corrupt base64 / malformed records → false, no crash', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '135790');

      const corruptRecords = <String>[
        'pbkdf2_sha256\$1000\$\$\$',                    // empty fields
        'pbkdf2_sha256\$1000\$!!!not-base64!\$@@@',     // invalid base64
        'pbkdf2_sha256\$abc\$aaaa\$bbbb',               // non-numeric rounds
        'pbkdf2_sha256\$0\$aaaa\$bbbb',                 // zero rounds
        'future_scheme\$1000\$aaaa\$bbbb',              // unknown marker
        'pbkdf2_sha256\$1000\$aaaa',                    // truncated
      ];
      for (final record in corruptRecords) {
        FlutterSecureStorage.setMockInitialValues({
          LockService.pinStorageKey: record,
        });
        expect(await lock.isNormalPin('135790'), isFalse,
            reason: 'Corrupt record "$record" must fail closed');
      }
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 7 — isLockEnabled reflects setup state
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 3.1 — Lock enablement lifecycle', () {
    test('disabled → enabled after setup → disabled after disableLock',
        () async {
      final lock = service();
      expect(await lock.isLockEnabled(), isFalse);

      await lock.setupSecurity(normalPin: '112233');
      expect(await lock.isLockEnabled(), isTrue);

      await lock.disableLock();
      expect(await lock.isLockEnabled(), isFalse);

      // PIN records are erased with the lock.
      expect(await lock.isNormalPin('112233'), isFalse);
      expect(await storage.read(key: LockService.pinStorageKey), isNull);
    });

    test('no PIN stored → verification fails closed even if flag stale',
        () async {
      FlutterSecureStorage.setMockInitialValues({
        LockService.enabledStorageKey: 'true',
      });
      final lock = service();

      expect(await lock.isLockEnabled(), isTrue);
      expect(await lock.isNormalPin('0000'), isFalse);
      expect(await lock.isDuressPin('0000'), isFalse);
    });
  });
}
