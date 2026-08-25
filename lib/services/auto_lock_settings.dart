import 'package:shared_preferences/shared_preferences.dart';

import '../core/constants.dart';

/// User-selectable auto-lock timeout policies (Node Settings).
///
/// The persisted value is the enum index under
/// [KamuiConstants.autoLockTimeoutPrefsKey]; when nothing is stored the
/// default is [AutoLockOption.immediate], matching
/// [KamuiConstants.autoLockTimeout].
enum AutoLockOption {
  immediate(KamuiConstants.autoLockTimeout, 'Immediate'),
  oneMinute(Duration(minutes: 1), '1 min'),
  fiveMinutes(Duration(minutes: 5), '5 min'),
  fifteenMinutes(Duration(minutes: 15), '15 min');

  const AutoLockOption(this.timeout, this.label);

  /// Background grace period before the lock gate engages.
  final Duration timeout;

  /// Short UI label rendered on the setting chips.
  final String label;

  /// Maps a persisted index back to an option. Null / out-of-range values
  /// fall back to [immediate] — corrupt preference data can never disable
  /// or extend the lock policy beyond the offered choices.
  static AutoLockOption fromIndex(int? index) {
    if (index == null || index < 0 || index >= AutoLockOption.values.length) {
      return AutoLockOption.immediate;
    }
    return AutoLockOption.values[index];
  }
}

/// Persistence seam for the auto-lock timeout user setting.
///
/// The lifecycle observer in `main.dart` calls [load] on every resume, so a
/// changed selection takes effect immediately — no app restart required
/// (SharedPreferences caches in memory after the first read).
class AutoLockSettings {
  AutoLockSettings._();

  /// Loads the persisted option; defaults to [AutoLockOption.immediate].
  static Future<AutoLockOption> loadOption() async {
    final prefs = await SharedPreferences.getInstance();
    return AutoLockOption.fromIndex(
      prefs.getInt(KamuiConstants.autoLockTimeoutPrefsKey),
    );
  }

  /// Loads the effective auto-lock timeout duration.
  static Future<Duration> load() async => (await loadOption()).timeout;

  /// Persists [option] as the active auto-lock policy.
  static Future<void> save(AutoLockOption option) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(KamuiConstants.autoLockTimeoutPrefsKey, option.index);
  }
}
