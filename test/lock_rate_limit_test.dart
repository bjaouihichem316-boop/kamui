// ══════════════════════════════════════════════════════════════════════════════
// Kamui Phase 6 — PIN attempt rate-limiting / lockout suite
//
// Covers:
//   1. Threshold: 4 failures tolerated, 5th arms a 30s lockout
//   2. Lockout blocks ALL verification (even the correct PIN) — identical
//      response regardless of whether the submitted value would be the
//      duress PIN, so lockout cannot leak duress membership
//   3. Lockout expiry re-enables verification (injectable clock)
//   4. Doubling windows per subsequent lockout, hard-capped at 15 minutes
//   5. Successful unlock resets failure AND escalation counters
//   6. Duress success resets the counters too
//   7. State persists across service recreation (SharedPreferences)
//   8. setupSecurity / disableLock clear rate-limit state
//
// Isolation follows the repo pattern: FlutterSecureStorage.setMockInitialValues
// + LockService.isolated, plus SharedPreferences mocks for the rate-limit
// store and an injectable clock instead of real delays.
// ══════════════════════════════════════════════════════════════════════════════

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/lock_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  /// Mutable fake clock shared with the service under test.
  DateTime fakeNow = DateTime(2026, 1, 1, 12, 0, 0);

  LockService service() =>
      LockService.isolated(iterations: 1000, clock: () => fakeNow);

  void advance(Duration d) => fakeNow = fakeNow.add(d);

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();
    await prefs.clear();
    fakeNow = DateTime(2026, 1, 1, 12, 0, 0);
  });

  group('Phase 6.A — threshold & first lockout', () {
    test('4 failures → denied & unlocked; 5th arms a 30s lockout', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');

      for (var i = 0; i < 4; i++) {
        final r = await lock.verifyPin('000000');
        expect(r.status, PinAttemptStatus.denied,
            reason: 'failure #${i + 1} must stay below the lockout threshold');
        expect(await lock.isLockedOut(), isFalse);
      }

      final fifth = await lock.verifyPin('000000');
      expect(fifth.status, PinAttemptStatus.lockedOut);
      expect(fifth.lockoutRemaining, LockService.initialLockout);
      expect(await lock.isLockedOut(), isTrue);
    });

    test('fresh install: never locked, remaining lockout is zero', () async {
      final lock = service();
      expect(await lock.isLockedOut(), isFalse);
      expect(await lock.remainingLockout(), Duration.zero);
    });
  });

  group('Phase 6.B — lockout semantics', () {
    test('during lockout even the CORRECT primary PIN is rejected', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');
      for (var i = 0; i < 5; i++) {
        await lock.verifyPin('000000');
      }

      final r = await lock.verifyPin('482913');
      expect(r.status, PinAttemptStatus.lockedOut,
          reason: 'no verification may run while locked out');
    });

    test('duress PIN gets the identical locked-out response (no leak)',
        () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913', duressPin: '112233');
      for (var i = 0; i < 5; i++) {
        await lock.verifyPin('000000');
      }

      final duressResult = await lock.verifyPin('112233');
      final wrongResult = await lock.verifyPin('999999');
      expect(duressResult.status, PinAttemptStatus.lockedOut);
      expect(wrongResult.status, PinAttemptStatus.lockedOut);
      expect(duressResult.lockoutRemaining, wrongResult.lockoutRemaining,
          reason: 'responses must be indistinguishable across PIN types');
    });

    test('expiry re-enables verification (injectable clock)', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');
      for (var i = 0; i < 5; i++) {
        await lock.verifyPin('000000');
      }
      expect(await lock.isLockedOut(), isTrue);

      advance(LockService.initialLockout);
      expect(await lock.remainingLockout(), Duration.zero);

      final r = await lock.verifyPin('482913');
      expect(r.status, PinAttemptStatus.primaryUnlocked);
    });

    test('one failure after expiry re-locks with the doubled window',
        () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');
      for (var i = 0; i < 5; i++) {
        await lock.verifyPin('000000'); // streak reaches 5 → lockout #1 (30s)
      }
      advance(LockService.initialLockout);

      // Counter was never reset (only success resets it), so the very next
      // failure fires lockout #2 with the doubled window.
      final r = await lock.verifyPin('000001');
      expect(r.status, PinAttemptStatus.lockedOut);
      expect(r.lockoutRemaining, const Duration(seconds: 60));
    });
  });

  group('Phase 6.C — escalation & cap', () {
    test('windows double 30s → 60s → … and cap at 15 minutes', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');

      // Round 1: the full 5-failure streak arms the base 30s window.
      for (var i = 0; i < 4; i++) {
        expect((await lock.verifyPin('111111')).status,
            PinAttemptStatus.denied);
      }
      var result = await lock.verifyPin('111111');
      expect(result.status, PinAttemptStatus.lockedOut);
      expect(result.lockoutRemaining, const Duration(seconds: 30));

      // Subsequent rounds: one failure per expired window, doubling to cap.
      // The counter was never reset, so every post-expiry failure fires the
      // next lockout immediately.
      var window = LockService.initialLockout;
      while (window < LockService.maxLockout) {
        advance(window);
        window = window * 2 > LockService.maxLockout
            ? LockService.maxLockout
            : window * 2;
        result = await lock.verifyPin('222222');
        expect(result.status, PinAttemptStatus.lockedOut);
        expect(result.lockoutRemaining, window);
      }

      // Cap holds: further failures never exceed 15 minutes.
      advance(window);
      result = await lock.verifyPin('333333');
      expect(result.status, PinAttemptStatus.lockedOut);
      expect(result.lockoutRemaining, LockService.maxLockout);
    });

    test('cap constant is 15 minutes and initial window 30 seconds', () {
      expect(LockService.maxConsecutiveFailures, 5);
      expect(LockService.initialLockout, const Duration(seconds: 30));
      expect(LockService.maxLockout, const Duration(minutes: 15));
    });
  });

  group('Phase 6.D — success resets', () {
    test('primary success clears failure AND escalation counters', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');

      // Reach lockout #1, expire it, then unlock legitimately.
      for (var i = 0; i < 5; i++) {
        await lock.verifyPin('000000');
      }
      advance(LockService.initialLockout);
      expect((await lock.verifyPin('482913')).status,
          PinAttemptStatus.primaryUnlocked);

      // A fresh full streak now arms only the BASE window again.
      for (var i = 0; i < 4; i++) {
        expect((await lock.verifyPin('000000')).status,
            PinAttemptStatus.denied);
      }
      final fifth = await lock.verifyPin('000000');
      expect(fifth.status, PinAttemptStatus.lockedOut);
      expect(fifth.lockoutRemaining, LockService.initialLockout,
          reason: 'successful unlock must restart escalation at 30s');
    });

    test('duress success resets the counters as well', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913', duressPin: '112233');

      for (var i = 0; i < 4; i++) {
        await lock.verifyPin('000000');
      }
      expect(
        (await lock.verifyPin('112233')).status,
        PinAttemptStatus.duressUnlocked,
      );

      for (var i = 0; i < 4; i++) {
        expect((await lock.verifyPin('000000')).status,
            PinAttemptStatus.denied,
            reason: 'counter must have been reset by the duress match');
      }
    });
  });

  group('Phase 6.E — persistence', () {
    test('lockout survives service recreation', () async {
      final first = service();
      await first.setupSecurity(normalPin: '482913');
      for (var i = 0; i < 5; i++) {
        await first.verifyPin('000000');
      }
      expect(await first.isLockedOut(), isTrue);

      // Brand-new instance over the same backing stores (app restart).
      final second = service();
      expect(await second.isLockedOut(), isTrue);
      expect((await second.verifyPin('482913')).status,
          PinAttemptStatus.lockedOut,
          reason: 'recreation must not bypass the persisted window');

      advance(LockService.initialLockout);
      expect(
        (await second.verifyPin('482913')).status,
        PinAttemptStatus.primaryUnlocked,
      );
    });

    test('failure counter persists across recreation mid-streak', () async {
      final first = service();
      await first.setupSecurity(normalPin: '482913');
      for (var i = 0; i < 3; i++) {
        await first.verifyPin('000000');
      }

      final second = service();
      // 3 + 1 = 4 failures → still below the threshold.
      expect((await second.verifyPin('000000')).status,
          PinAttemptStatus.denied);
      // 5th failure crosses it.
      expect((await second.verifyPin('000000')).status,
          PinAttemptStatus.lockedOut);
    });
  });

  group('Phase 6.F — lifecycle resets', () {
    test('re-running setupSecurity clears an active lockout', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');
      for (var i = 0; i < 5; i++) {
        await lock.verifyPin('000000');
      }
      expect(await lock.isLockedOut(), isTrue);

      await lock.setupSecurity(normalPin: '482913', duressPin: '112233');
      expect(await lock.isLockedOut(), isFalse);
      expect((await lock.verifyPin('482913')).status,
          PinAttemptStatus.primaryUnlocked);
    });

    test('disableLock clears an active lockout', () async {
      final lock = service();
      await lock.setupSecurity(normalPin: '482913');
      for (var i = 0; i < 5; i++) {
        await lock.verifyPin('000000');
      }
      expect(await lock.isLockedOut(), isTrue);

      await lock.disableLock();
      expect(await lock.isLockedOut(), isFalse);
      expect(await lock.remainingLockout(), Duration.zero);
    });
  });
}
