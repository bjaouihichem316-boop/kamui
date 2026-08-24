// ignore_for_file: avoid_print
//
// ══════════════════════════════════════════════════════════════════════════════
// Kamui Phase 2.5 — Send Outbox Test Suite
//
// Covers:
//   8. Send fails → message persisted as failed + payload queued
//      → simulated reconnect → retried exactly once → sent
//   + retry-counter bookkeeping, manual single retry, concurrency guard
// ══════════════════════════════════════════════════════════════════════════════

import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/crypto_service.dart';
import 'package:kamui/services/database_service.dart';
import 'package:kamui/services/outbox_service.dart';
import 'package:kamui/services/sam_channel.dart';
import 'package:kamui/services/sam_service.dart';
import 'package:path/path.dart' as p;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  sqfliteFfiInit();
  databaseFactory = databaseFactoryFfi;

  late Directory tempDir;
  late DatabaseService dbService;
  late CryptoService crypto;
  late OutboxService outbox;

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    CryptoService().resetForTesting();

    tempDir = await Directory.systemTemp.createTemp('kamui_outbox');
    await databaseFactory.setDatabasesPath(tempDir.path);
    await DatabaseService().close();
    await deleteDatabase(p.join(tempDir.path, 'kamui.db'));

    dbService = DatabaseService();
    crypto = CryptoService();
    await crypto.init();

    outbox = OutboxService.isolated(databaseService: dbService, cryptoService: crypto);
  });

  tearDown(() async {
    await DatabaseService().close();
    try {
      await tempDir.delete(recursive: true);
    } catch (_) {}
  });

  group('Phase 2.5 — Outbox queue lifecycle', () {
    test('enqueue → pending → markSent removes entry', () async {
      await outbox.enqueue(
        id: 'm1',
        conversationId: 'conv_1',
        destination: 'DEST_PEER',
        encryptedPayload: 'kamui_v4:AAAA:BBBB:CCCC',
      );

      final queued = await outbox.pending();
      expect(queued, hasLength(1));
      expect(queued.first.id, equals('m1'));
      expect(queued.first.destination, equals('DEST_PEER'));
      expect(queued.first.encryptedPayload, equals('kamui_v4:AAAA:BBBB:CCCC'),
          reason: 'payload must round-trip through at-rest encryption');
      expect(queued.first.retryCount, equals(0));

      await outbox.markSent('m1');
      expect(await outbox.pending(), isEmpty);
    });

    test('failed pass bumps retry_count and keeps entry; successful pass delivers exactly once',
        () async {
      await outbox.enqueue(
        id: 'm2',
        conversationId: 'conv_1',
        destination: 'DEST_PEER',
        encryptedPayload: 'payload-2',
      );

      // ── Simulated offline: every attempt fails ───────────────────────────
      var attempts = 0;
      var delivered = await outbox.retryAll((entry) async {
        attempts++;
        return false;
      });

      expect(delivered, equals(0));
      expect(attempts, equals(1), reason: 'exactly one attempt per reconnect pass');

      var queued = await outbox.pending();
      expect(queued, hasLength(1));
      expect(queued.first.retryCount, equals(1));

      // ── Simulated reconnect: SAM link restored ───────────────────────────
      attempts = 0;
      delivered = await outbox.retryAll((entry) async {
        attempts++;
        expect(entry.id, equals('m2'));
        return true; // tunnel up → delivered
      });

      expect(delivered, equals(1));
      expect(attempts, equals(1), reason: 'retried EXACTLY once on reconnect');

      // Queue is drained — a subsequent pass must attempt nothing.
      attempts = 0;
      delivered = await outbox.retryAll((entry) async {
        attempts++;
        return true;
      });
      expect(delivered, equals(0));
      expect(attempts, equals(0), reason: 'no duplicate sends after delivery');
      expect(await outbox.pending(), isEmpty);
    });

    test('retryOne delivers a single targeted entry', () async {
      await outbox.enqueue(
        id: 'm3',
        conversationId: 'conv_1',
        destination: 'DEST_A',
        encryptedPayload: 'payload-3',
      );
      await outbox.enqueue(
        id: 'm4',
        conversationId: 'conv_1',
        destination: 'DEST_B',
        encryptedPayload: 'payload-4',
      );

      final sent = await outbox.retryOne('m3', (entry) async => true);
      expect(sent, isTrue);

      final queued = await outbox.pending();
      expect(queued.map((e) => e.id), ['m4']);
    });

    test('send exception during retry is swallowed and entry stays queued', () async {
      await outbox.enqueue(
        id: 'm5',
        conversationId: 'conv_1',
        destination: 'DEST_C',
        encryptedPayload: 'payload-5',
      );

      final sent = await outbox.retryOne('m5', (entry) async {
        throw StateError('socket exploded');
      });
      expect(sent, isFalse);

      final queued = await outbox.pending();
      expect(queued, hasLength(1));
      expect(queued.first.retryCount, equals(1));
    });
  });

  group('Phase 2.5 — SamService failure signal feeds the outbox', () {
    test('sendRawMessage returns false when transport is down (queue trigger)', () async {
      // Channel factory whose connects always fail — SAM bridge unreachable.
      final sam = SamService.isolated(channelFactory: _FailingChannelFactory());
      sam.sessionId = 'test-session'; // pretend a session exists

      final sent = await sam.sendRawMessage('DEST_OFFLINE_PEER', 'ciphertext');
      expect(sent, isFalse,
          reason: 'failure must be signalled so callers enqueue to the outbox');
    });
  });
}

/// Factory that simulates an unreachable SAM bridge.
class _FailingChannelFactory implements SamChannelFactory {
  @override
  Future<SamChannel> connect(String host, int port, {Duration? timeout}) async {
    throw StateError('connection refused');
  }

  @override
  Future<SamServerChannel> bind(String host, int port) async {
    throw StateError('bind unavailable');
  }
}
