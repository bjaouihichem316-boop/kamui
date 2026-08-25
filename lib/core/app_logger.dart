import 'package:flutter/foundation.dart';

/// Severity levels for [AppLogger], ordered from least to most severe.
enum LogLevel {
  /// Verbose diagnostic detail — suppressed in release builds.
  debug,

  /// Routine lifecycle events — suppressed in release builds.
  info,

  /// Unexpected but recoverable conditions — always logged.
  warning,

  /// Failures that lose data or break a feature — always logged.
  error;

  /// Uppercase label rendered in the log-line prefix.
  String get label => switch (this) {
        LogLevel.debug => 'DEBUG',
        LogLevel.info => 'INFO',
        LogLevel.warning => 'WARN',
        LogLevel.error => 'ERROR',
      };
}

/// Minimal structured logger for Kamui.
///
/// - Output goes through [debugPrint] (no-ops when the app is not attached).
/// - Every line is prefixed `[LEVEL][tag]` so logs are greppable per module.
/// - Release gating: [LogLevel.debug] and [LogLevel.info] are no-ops when
///   [AppLogger.releaseMode] is `true`; warnings and errors are ALWAYS logged
///   because they mark real faults (data loss, wipe failures, desyncs).
///
/// Usage:
/// ```dart
/// static const AppLogger _log = AppLogger('DatabaseService');
/// _log.w('Nuke: cache cleanup failed');
/// ```
class AppLogger {
  /// Injectable release flag. Defaults to `!kDebugMode` so release/profile
  /// builds gate automatically; tests flip this to exercise both branches.
  static bool releaseMode = !kDebugMode;

  /// Module name rendered as `[LEVEL][$tag]` on every line.
  final String tag;

  const AppLogger(this.tag);

  /// Logs a verbose diagnostic message (suppressed in release builds).
  void d(String message) => log(LogLevel.debug, message);

  /// Logs a routine lifecycle event (suppressed in release builds).
  void i(String message) => log(LogLevel.info, message);

  /// Logs an unexpected-but-recoverable condition (always logged).
  void w(String message) => log(LogLevel.warning, message);

  /// Logs a failure. The optional [error] object is appended for context —
  /// never pass key material or payload contents here.
  void e(String message, [Object? error]) =>
      log(LogLevel.error, error == null ? message : '$message ($error)');

  /// Emits [message] at [level], honoring the release-mode gate.
  void log(LogLevel level, String message) {
    if (releaseMode && (level == LogLevel.debug || level == LogLevel.info)) {
      return;
    }
    debugPrint('[${level.label}][$tag] $message');
  }
}
