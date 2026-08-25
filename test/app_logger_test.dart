import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:kamui/core/app_logger.dart';

void main() {
  final List<String> lines = <String>[];

  setUp(() {
    lines.clear();
    // Capture everything the logger would print.
    debugPrint = (String? message, {int? wrapWidth}) {
      if (message != null) lines.add(message);
    };
  });

  tearDown(() {
    debugPrint = debugPrintThrottled;
    AppLogger.releaseMode = !kDebugMode; // restore default
  });

  group('AppLogger', () {
    test('defaults to release gating derived from kDebugMode', () {
      expect(AppLogger.releaseMode, !kDebugMode);
    });

    test('emits every level in debug builds', () {
      AppLogger.releaseMode = false;
      const log = AppLogger('Test');

      log.d('detail');
      log.i('lifecycle');
      log.w('recoverable');
      log.e('failure');

      expect(lines, hasLength(4));
      expect(lines[0], '[DEBUG][Test] detail');
      expect(lines[1], '[INFO][Test] lifecycle');
      expect(lines[2], '[WARN][Test] recoverable');
      expect(lines[3], '[ERROR][Test] failure');
    });

    test('suppresses debug/info but keeps warn/error in release builds', () {
      AppLogger.releaseMode = true;
      const log = AppLogger('Test');

      log.d('hidden detail');
      log.i('hidden lifecycle');
      log.w('visible warning');
      log.e('visible failure');

      expect(lines, hasLength(2));
      expect(lines[0], '[WARN][Test] visible warning');
      expect(lines[1], '[ERROR][Test] visible failure');
    });

    test('log() honors the same gating as the level helpers', () {
      AppLogger.releaseMode = true;
      const log = AppLogger('Gate');

      log.log(LogLevel.debug, 'gated out');
      log.log(LogLevel.info, 'gated out too');
      log.log(LogLevel.warning, 'passes');
      log.log(LogLevel.error, 'passes as well');

      expect(lines, [
        '[WARN][Gate] passes',
        '[ERROR][Gate] passes as well',
      ]);
    });

    test('e() appends the optional error object for context', () {
      AppLogger.releaseMode = true;
      const log = AppLogger('Ctx');

      log.e('Operation failed', StateError('boom'));

      expect(lines, hasLength(1));
      expect(lines.single, startsWith('[ERROR][Ctx] Operation failed ('));
      expect(lines.single, contains('boom'));
    });
  });
}
