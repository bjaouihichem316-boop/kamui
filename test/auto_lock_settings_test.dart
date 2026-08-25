// ══════════════════════════════════════════════════════════════════════════════
// Kamui Phase 6 — Auto-lock timeout user setting suite
//
// Covers:
//   1. Default policy when nothing is persisted = KamuiConstants.autoLockTimeout
//   2. Persistence round-trip for every AutoLockOption
//   3. Corrupt / out-of-range persisted indices fall back to Immediate
//   4. Option table sanity (4 choices, strictly increasing, labeled)
//
// Unit-tests the settings store logic only — full widget tests are not
// required per the work-package spec.
// ══════════════════════════════════════════════════════════════════════════════

import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/core/constants.dart';
import 'package:kamui/services/auto_lock_settings.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();
    await prefs.clear();
  });

  group('Phase 6.G — default policy', () {
    test('unset preference falls back to KamuiConstants.autoLockTimeout',
        () async {
      expect(await AutoLockSettings.loadOption(), AutoLockOption.immediate);
      expect(await AutoLockSettings.load(), Duration.zero);
      expect(await AutoLockSettings.load(), KamuiConstants.autoLockTimeout,
          reason: 'the constant is documented as the DEFAULT when unset');
    });
  });

  group('Phase 6.H — persistence round-trip', () {
    test('every option survives save → load', () async {
      for (final option in AutoLockOption.values) {
        await AutoLockSettings.save(option);

        final loaded = await AutoLockSettings.loadOption();
        expect(loaded, option, reason: '${option.label} must round-trip');
        expect(await AutoLockSettings.load(), option.timeout);
      }
    });

    test('last write wins', () async {
      await AutoLockSettings.save(AutoLockOption.fiveMinutes);
      await AutoLockSettings.save(AutoLockOption.oneMinute);
      expect(await AutoLockSettings.loadOption(), AutoLockOption.oneMinute);
    });
  });

  group('Phase 6.I — corrupt data fallback', () {
    test('out-of-range index falls back to Immediate', () async {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt(KamuiConstants.autoLockTimeoutPrefsKey, 99);
      expect(await AutoLockSettings.loadOption(), AutoLockOption.immediate);

      await prefs.setInt(KamuiConstants.autoLockTimeoutPrefsKey, -3);
      expect(await AutoLockSettings.loadOption(), AutoLockOption.immediate);
    });

    test('fromIndex handles null and boundary indices', () {
      expect(AutoLockOption.fromIndex(null), AutoLockOption.immediate);
      expect(AutoLockOption.fromIndex(-1), AutoLockOption.immediate);
      expect(
        AutoLockOption.fromIndex(AutoLockOption.values.length),
        AutoLockOption.immediate,
      );
      expect(AutoLockOption.fromIndex(0), AutoLockOption.immediate);
      expect(
        AutoLockOption.fromIndex(AutoLockOption.values.length - 1),
        AutoLockOption.values.last,
      );
    });
  });

  group('Phase 6.J — option table sanity', () {
    test('four choices: Immediate / 1 min / 5 min / 15 min', () {
      expect(AutoLockOption.values, hasLength(4));
      expect(AutoLockOption.values.map((o) => o.timeout).toList(), [
        Duration.zero,
        const Duration(minutes: 1),
        const Duration(minutes: 5),
        const Duration(minutes: 15),
      ]);
    });

    test('timeouts are strictly increasing and labels non-empty', () {
      final timeouts = AutoLockOption.values.map((o) => o.timeout).toList();
      for (var i = 1; i < timeouts.length; i++) {
        expect(timeouts[i], greaterThan(timeouts[i - 1]),
            reason: 'chips render in enum order — must be increasing');
      }
      for (final o in AutoLockOption.values) {
        expect(o.label, isNotEmpty);
      }
    });
  });
}
