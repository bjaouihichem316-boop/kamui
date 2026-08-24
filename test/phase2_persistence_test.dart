// ignore_for_file: avoid_print
//
// ══════════════════════════════════════════════════════════════════════════════
// Kamui Phase 2 — Persistence & Protocol Completeness Test Suite
//
// Covers:
//   1. SQLite v2 → v3 migration (contacts identity columns, sessions, outbox)
//   2. Contact PreKeyBundle persistence round-trip (+ COALESCE upsert safety)
//   3. Double Ratchet serialize/deserialize round-trip with skipped keys
//   4. Corrupt / tampered session blobs → clean discard, no crash
//   5. Restart mid-conversation: sessions restored from store, replay rejected
//   6. Two sequential handshakes against ONE published bundle both succeed
//   7. QR handshake payload length bound
// ══════════════════════════════════════════════════════════════════════════════

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/models/contact.dart';
import 'package:kamui/models/conversation.dart';
import 'package:kamui/repositories/conversation_repository_impl.dart';
import 'package:kamui/services/crypto_service.dart';
import 'package:kamui/services/database_service.dart';
import 'package:kamui/services/double_ratchet.dart';
import 'package:kamui/services/identity_key_service.dart';
import 'package:kamui/services/session_manager.dart';
import 'package:kamui/services/session_store.dart';
import 'package:kamui/services/x3dh_service.dart';
import 'package:path/path.dart' as p;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  sqfliteFfiInit();
  databaseFactory = databaseFactoryFfi;

  final ed25519 = Ed25519();
  final x25519  = X25519();

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    CryptoService().resetForTesting();
    IdentityKeyService().resetForTesting();
    await DatabaseService().close();
  });

  // ── Real-SQLite harness ────────────────────────────────────────────────────
  Directory? tempDir;

  Future<String> freshDbPath() async {
    tempDir = await Directory.systemTemp.createTemp('kamui_phase2');
    await databaseFactory.setDatabasesPath(tempDir!.path);
    return p.join(tempDir!.path, 'kamui.db');
  }

  /// Creates a genuine schema-v2 database (pre-Phase-2 install) at [path].
  Future<void> createV2Database(String path) async {
    final db = await databaseFactory.openDatabase(path);
    await db.execute('''
      CREATE TABLE contacts (
        id              TEXT PRIMARY KEY,
        name            TEXT NOT NULL,
        destination     TEXT NOT NULL UNIQUE,
        avatar_initial  TEXT NOT NULL DEFAULT '?',
        status          TEXT NOT NULL DEFAULT 'offline',
        last_seen       INTEGER,
        created_at      INTEGER NOT NULL
      )
    ''');
    await db.execute('''
      CREATE TABLE conversations (
        id              TEXT PRIMARY KEY,
        contact_id      TEXT NOT NULL,
        unread_count    INTEGER NOT NULL DEFAULT 0,
        created_at      INTEGER NOT NULL,
        updated_at      INTEGER NOT NULL,
        FOREIGN KEY (contact_id) REFERENCES contacts (id) ON DELETE CASCADE
      )
    ''');
    await db.execute('''
      CREATE TABLE messages (
        id                TEXT PRIMARY KEY,
        conversation_id   TEXT NOT NULL,
        encrypted_text    TEXT NOT NULL,
        timestamp         INTEGER NOT NULL,
        is_sent           INTEGER NOT NULL DEFAULT 1,
        is_encrypted      INTEGER NOT NULL DEFAULT 1,
        status            TEXT NOT NULL DEFAULT 'sent',
        ttl_seconds       INTEGER,
        expires_at        INTEGER,
        FOREIGN KEY (conversation_id) REFERENCES conversations (id) ON DELETE CASCADE
      )
    ''');
    await db.execute(
      'CREATE INDEX idx_messages_conv ON messages (conversation_id, timestamp)',
    );
    // Mark the file as a genuine v2 install so openDatabase(version:3) takes
    // the onUpgrade(2→3) path instead of onCreate.
    await db.execute('PRAGMA user_version = 2');
    await db.close();
  }

  tearDown(() async {
    await DatabaseService().close();
    try {
      await tempDir?.delete(recursive: true);
    } catch (_) {}
    tempDir = null;
  });

  // ── Crypto harness (Alice ↔ Bob Double Ratchet pair) ──────────────────────
  Future<({
    DoubleRatchetSession aliceSession,
    DoubleRatchetSession bobSession,
  })> setupSessionPair({String convId = 'adv-conv'}) async {
    final ikEdB = await ed25519.newKeyPair();
    final ikDhB = await x25519.newKeyPair();
    final spkB  = await x25519.newKeyPair();
    final opkB  = await x25519.newKeyPair();

    final spkBPub = await spkB.extractPublicKey();
    final spkSig  = await ed25519.sign(spkBPub.bytes, keyPair: ikEdB);

    final bundle = PreKeyBundle(
      ikPubEd: (await ikEdB.extractPublicKey()).bytes,
      ikPubDh: (await ikDhB.extractPublicKey()).bytes,
      spkPub:  spkBPub.bytes,
      spkSig:  spkSig.bytes,
      opkId:   1,
      opkPub:  (await opkB.extractPublicKey()).bytes,
    );

    final aliceIkDh    = await x25519.newKeyPair();
    final aliceIkDhPub = await aliceIkDh.extractPublicKey();

    final aliceX3dh = await X3dhService.initiatorHandshake(
      ikADh: aliceIkDh,
      bundleB: bundle,
    );

    final aliceSession = await DoubleRatchetSession.initAlice(
      conversationId: convId,
      peerIdentityPublicKeyB64: 'PEER=',
      sk: aliceX3dh.sharedSecret,
      bobSpkPub: bundle.spkPub,
    );

    final bobSk = await X3dhService.responderHandshake(
      ikBDh: ikDhB,
      spkB: spkB,
      opkB: opkB,
      ekAPub: aliceX3dh.ekPub,
      ikADhPub: aliceIkDhPub.bytes,
    );

    final bobSession = await DoubleRatchetSession.initBob(
      conversationId: convId,
      peerIdentityPublicKeyB64: 'PEER=',
      sk: bobSk,
      spkBDh: spkB,
    );

    return (aliceSession: aliceSession, bobSession: bobSession);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 1 — Migration v2 → v3
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2.1 — SQLite migration v2 → v3', () {
    test('v2 DB with existing contact opens under v3; new columns are null-safe', () async {
      final path = await freshDbPath();
      await createV2Database(path);

      // Seed a pre-migration contact row.
      final seed = await databaseFactory.openDatabase(path);
      await seed.insert('contacts', {
        'id': 'c_legacy',
        'name': 'Legacy Peer',
        'destination': 'LEGACY_DEST_KEY',
        'avatar_initial': 'L',
        'status': 'offline',
        'created_at': 1000,
      });
      await seed.close();

      // Open through DatabaseService → triggers _onUpgrade(2 → 3).
      final db = await DatabaseService().db;

      // Legacy contact survives with null-safe new columns.
      final rows = await db.query('contacts', where: 'id = ?', whereArgs: ['c_legacy']);
      expect(rows, hasLength(1));
      expect(rows.first['identity_public_key'], isNull);
      expect(rows.first['pre_key_bundle_json'], isNull);

      // New v3 tables exist and accept writes.
      await db.insert('sessions', {
        'conversation_id': 'conv_x',
        'encrypted_state': 'blob',
        'updated_at': 1234,
      });
      final sess = await db.query('sessions');
      expect(sess, hasLength(1));

      await db.insert('outbox', {
        'id': 'm1',
        'conversation_id': 'conv_x',
        'destination': 'DEST',
        'encrypted_payload': 'payload',
        'created_at': 1234,
        'retry_count': 0,
      });
      final outbox = await db.query('outbox');
      expect(outbox, hasLength(1));
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 2 — Contact PreKeyBundle persistence round-trip
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2.1 — Contact identity keys + PreKeyBundle round-trip', () {
    test('save with bundle → getAll() returns identical preKeyBundleJson', () async {
      await freshDbPath();
      await CryptoService().init();

      const bundleJson =
          '{"ik_ed":"AAAA","ik_dh":"BBBB","spk":"CCCC","spk_sig":"DDDD",'
          '"opk_id":2,"opk":"EEEE","opks":{"1":"EEEE","2":"FFFF"}}';

      final repo = ConversationRepositoryImpl(DatabaseService(), CryptoService());
      final conv = Conversation(
        id: 'conv_rt',
        contact: const Contact(
          id: 'c_rt',
          name: 'Roundtrip',
          destination: 'DEST_RT',
          identityPublicKey: 'IDPUB=',
          preKeyBundleJson: bundleJson,
          avatarInitial: 'R',
        ),
      );

      await repo.save(conv);
      final all = await repo.getAll();

      expect(all, hasLength(1));
      expect(all.first.contact.preKeyBundleJson, equals(bundleJson));
      expect(all.first.contact.identityPublicKey, equals('IDPUB='));
    });

    test('re-saving a bare contact does NOT null out stored bundle (COALESCE upsert)', () async {
      await freshDbPath();
      await CryptoService().init();

      const bundleJson = '{"ik_ed":"AAAA","v":3}';
      final repo = ConversationRepositoryImpl(DatabaseService(), CryptoService());

      await repo.save(Conversation(
        id: 'conv_c',
        contact: const Contact(
          id: 'c_c',
          name: 'Peer',
          destination: 'DEST_C',
          identityPublicKey: 'IDPUB=',
          preKeyBundleJson: bundleJson,
          avatarInitial: 'P',
        ),
      ));

      // Inbound-message flow re-saves the same contact WITHOUT key material.
      await repo.save(Conversation(
        id: 'conv_c',
        contact: const Contact(
          id: 'c_c',
          name: 'Peer Renamed',
          destination: 'DEST_C',
          avatarInitial: 'P',
        ),
      ));

      final all = await repo.getAll();
      expect(all.first.contact.name, equals('Peer Renamed'));
      expect(all.first.contact.preKeyBundleJson, equals(bundleJson),
          reason: 'COALESCE upsert must preserve persisted bundle');
      expect(all.first.contact.identityPublicKey, equals('IDPUB='));
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 3 — Ratchet serialization round-trip with skipped keys
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2.2 — Double Ratchet persistent state round-trip', () {
    test('12-message history + 3 skipped keys → serialize → deserialize → seamless decrypt',
        () async {
      final pair = await setupSessionPair();
      final alice = pair.aliceSession;
      final bob   = pair.bobSession;

      // 9 interleaved exchanges (18 messages of processed history)…
      for (var i = 0; i < 9; i++) {
        final aWire = await alice.encrypt('alice-$i');
        expect(await bob.decrypt(aWire), equals('alice-$i'));
        final bWire = await bob.encrypt('bob-$i');
        expect(await alice.decrypt(bWire), equals('bob-$i'));
      }
      // …then 4 unanswered Alice messages in the SAME sending chain. Bob
      // decrypts only the LAST one — skipping 9,10,11 creates exactly 3
      // skipped message keys at his side.
      final pending = <String>[];
      for (var i = 9; i < 13; i++) {
        pending.add(await alice.encrypt('pending-$i'));
      }
      expect(await bob.decrypt(pending[3]), equals('pending-12'));
      expect(bob.skippedKeyCount, equals(3));

      // Serialize ONLY now (post-commit state).
      final blobMap = await bob.toPersistentJson();
      expect(blobMap['version'], equals(kPersistentStateVersion));
      final blob = jsonEncode(blobMap);

      // "Dispose" Bob and rebuild purely from the serialized blob.
      final restored = await DoubleRatchetSession.fromPersistentJson(
        jsonDecode(blob) as Map<String, dynamic>,
      );
      expect(restored.skippedKeyCount, equals(3));

      // The 3 skipped messages decrypt seamlessly out of order.
      expect(await restored.decrypt(pending[0]), equals('pending-9'));
      expect(await restored.decrypt(pending[1]), equals('pending-10'));
      expect(await restored.decrypt(pending[2]), equals('pending-11'));

      // Conversation continues without any desync.
      final nextWire = await alice.encrypt('post-restart-msg');
      expect(await restored.decrypt(nextWire), equals('post-restart-msg'));

      // And the restored session can encrypt too (Bob replies).
      final replyWire = await restored.encrypt('bob-reply-after-restore');
      expect(await alice.decrypt(replyWire), equals('bob-reply-after-restore'));
    });

    test('skipped-key TTL creation timestamps survive serialization', () async {
      final pair = await setupSessionPair();
      final alice = pair.aliceSession;
      final bob   = pair.bobSession;

      // Three messages in one sending chain; Bob decrypts only the last →
      // two skipped keys with real TTL timestamps.
      final m0 = await alice.encrypt('s0');
      final m1 = await alice.encrypt('s1');
      final m2 = await alice.encrypt('s2');
      expect(await bob.decrypt(m2), equals('s2'));
      expect(bob.skippedKeyCount, equals(2));

      final blobMap = await bob.toPersistentJson();
      final skippedBefore =
          (blobMap['skipped'] as List).cast<Map<String, dynamic>>().toList()
            ..sort((a, b) => (a['n'] as int).compareTo(b['n'] as int));
      expect(skippedBefore.map((e) => e['n']), [0, 1]);
      expect(skippedBefore.every((e) => e['created_ms'] is int), isTrue);

      final restored = await DoubleRatchetSession.fromPersistentJson(
        jsonDecode(jsonEncode(blobMap)) as Map<String, dynamic>,
      );
      expect(restored.skippedKeyCount, equals(2));

      // Consuming the skipped keys still works after the round-trip.
      expect(await restored.decrypt(m0), equals('s0'));
      expect(await restored.decrypt(m1), equals('s1'));
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 4 — Corrupt / tampered session blobs fail clean
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2.3 — Corrupt session blob handling', () {
    test('garbage JSON, tampered ciphertext and bad version all restore to null — no crash',
        () async {
      final store = InMemorySessionStore();
      final identity = IdentityKeyService.isolated();
      await identity.init();

      // Case A: undecryptable garbage in the store.
      await store.saveEncryptedState('conv_a', 'definitely-not-json');

      // Case B: valid JSON but unsupported version.
      await store.saveEncryptedState(
        'conv_b',
        jsonEncode({'version': 99, 'rk': 'AAAA'}),
      );

      // Case C: structurally broken ratchet payload.
      await store.saveEncryptedState(
        'conv_c',
        jsonEncode({
          'version': kPersistentStateVersion,
          'conversation_id': 'conv_c',
          'peer_ik': 'PEER=',
          // missing rk / dh_s / counters / skipped
        }),
      );

      for (final convId in ['conv_a', 'conv_b', 'conv_c']) {
        final manager =
            SessionManager.isolated(identityService: identity, sessionStore: store);

        // Restore fails clean → manager falls through to fresh establishment;
        // with a deliberately unusable bundle that path throws fail-closed
        // (SessionUnavailableException) instead of crashing or half-restoring.
        await expectLater(
          manager.getOrCreateV4Session(
            convId,
            peerPreKeyBundleJson: '{"ik_ed":"AAAA"}',
          ),
          throwsA(isA<SessionUnavailableException>()),
          reason: '$convId must fail closed without crashing',
        );

        // The corrupt blob was discarded by the restore attempt.
        expect(await store.loadEncryptedState(convId), isNull,
            reason: '$convId corrupt blob must be deleted, not retried forever');
      }

      // Direct serializer contract: malformed input throws RatchetException.
      expect(
        () => DoubleRatchetSession.fromPersistentJson({'version': 42}),
        throwsA(isA<RatchetException>()),
      );
    });

    test('corrupt persisted blob is discarded and fresh X3DH succeeds afterwards', () async {
      final store = InMemorySessionStore();
      final aliceIdentity = IdentityKeyService.isolated();
      final bobIdentity   = IdentityKeyService.isolated();
      await aliceIdentity.init();
      await bobIdentity.init();

      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final bundleJson = jsonEncode(bobBundle!.toJson());

      // Poison the store for this conversation.
      await store.saveEncryptedState('conv_heal', '\x00\x01corrupted-blob');

      final aliceMgr = SessionManager.isolated(
        identityService: aliceIdentity,
        sessionStore: store,
      );
      final bobMgr = SessionManager.isolated(
        identityService: bobIdentity,
        sessionStore: store,
      );

      // Establishment proceeds cleanly despite the poisoned blob.
      final wire = await aliceMgr.encryptV4('conv_heal', 'hello after corruption',
          peerPreKeyBundleJson: bundleJson);
      final plain = await bobMgr.decryptV4('conv_heal', wire);
      expect(plain, equals('hello after corruption'));
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 5 — Restart mid-conversation
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2.3 — Restart mid-conversation restores Double Ratchet sessions', () {
    test('5-message exchange → dispose managers → recreate → next message decrypts; replay rejected',
        () async {
      // Per-device stores — each party persists under its own device storage
      // (in production these are two different phones' SQLite databases).
      final aliceStore = InMemorySessionStore();
      final bobStore   = InMemorySessionStore();

      final aliceIdentity = IdentityKeyService.isolated();
      final bobIdentity   = IdentityKeyService.isolated();
      await aliceIdentity.init();
      await bobIdentity.init();

      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final bundleJson = jsonEncode(bobBundle!.toJson());

      var aliceMgr = SessionManager.isolated(identityService: aliceIdentity, sessionStore: aliceStore);
      var bobMgr   = SessionManager.isolated(identityService: bobIdentity, sessionStore: bobStore);

      const convId = 'conv_restart';

      // ── Exchange 5 messages over the live wire ────────────────────────────
      final wireA1 = await aliceMgr.encryptV4(convId, 'msg-1-alice',
          peerPreKeyBundleJson: bundleJson);
      expect(await bobMgr.decryptV4(convId, wireA1), equals('msg-1-alice'));

      final wireB1 = await bobMgr.encryptV4(convId, 'msg-2-bob');
      expect(await aliceMgr.decryptV4(convId, wireB1), equals('msg-2-bob'));

      final wireA2 = await aliceMgr.encryptV4(convId, 'msg-3-alice');
      expect(await bobMgr.decryptV4(convId, wireA2), equals('msg-3-alice'));

      final wireB2 = await bobMgr.encryptV4(convId, 'msg-4-bob');
      expect(await aliceMgr.decryptV4(convId, wireB2), equals('msg-4-bob'));

      final wireA3 = await aliceMgr.encryptV4(convId, 'msg-5-alice');
      expect(await bobMgr.decryptV4(convId, wireA3), equals('msg-5-alice'));

      // ── RESTART: dispose both managers, recreate against the same stores ──
      aliceMgr = SessionManager.isolated(identityService: aliceIdentity, sessionStore: aliceStore);
      bobMgr   = SessionManager.isolated(identityService: bobIdentity, sessionStore: bobStore);

      // Alice's next send must be a NORMAL ratchet frame (session restored —
      // NOT a fresh HandshakeInitEnvelope, which would desync both sides).
      final wireA4 = await aliceMgr.encryptV4(convId, 'msg-6-after-restart');
      expect(wireA4.startsWith('kamui_v4:'), isTrue,
          reason: 'restored session must continue ratcheting, not re-handshake');
      expect(await bobMgr.decryptV4(convId, wireA4), equals('msg-6-after-restart'));

      // Bob replies through his restored session.
      final wireB3 = await bobMgr.encryptV4(convId, 'msg-7-bob-after-restart');
      expect(wireB3.startsWith('kamui_v4:'), isTrue);
      expect(await aliceMgr.decryptV4(convId, wireB3), equals('msg-7-bob-after-restart'));

      // Pre-restart replay is still rejected fail-closed.
      expect(
        () async => await bobMgr.decryptV4(convId, wireA1),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'replaying a pre-restart wire payload must be rejected',
      );

      // Rejected replay must not corrupt the restored ratchet state.
      final wireA5 = await aliceMgr.encryptV4(convId, 'msg-8-still-alive');
      expect(await bobMgr.decryptV4(convId, wireA5), equals('msg-8-still-alive'));
    });

    test('reset() wipes persisted session state (duress wipe)', () async {
      final store = InMemorySessionStore();
      final identity = IdentityKeyService.isolated();
      await identity.init();

      final mgr = SessionManager.isolated(identityService: identity, sessionStore: store);
      await store.saveEncryptedState('conv_wipe', '{}');
      expect(await store.loadEncryptedState('conv_wipe'), isNotNull);

      await mgr.reset();
      expect(await store.loadEncryptedState('conv_wipe'), isNull);
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 6 — Two sequential handshakes against ONE published bundle
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2.4 — OPK pool sustains multiple offline handshakes', () {
    late IdentityKeyService bobIdentity;
    late String publishedBundleJson;
    late PreKeyBundle publishedBundle;
    late SimpleKeyPair bobSpk;

    setUp(() async {
      bobIdentity = IdentityKeyService.isolated();
      await bobIdentity.init();

      final bundle = await bobIdentity.generatePreKeyBundleAsync();
      expect(bundle!.opks.length, equals(kOpkPoolSize),
          reason: 'fresh keyset must publish the full OPK pool');
      expect(bundle.opkId, equals(1), reason: 'legacy mirror points at first pool entry');

      publishedBundleJson = jsonEncode(bundle.toJson());
      publishedBundle = PreKeyBundle.fromJson(jsonDecode(publishedBundleJson));
      bobSpk = bobIdentity.spkKeyPair!;
    });

    Future<SimpleKeyPair> newAliceIdentity() => x25519.newKeyPair();

    test('two sequential handshakes against ONE published bundle both succeed; '
        'consumed-OPK reuse is rejected', () async {
      // ── Handshake 1 (Alice₁ uses pool OPK id 1) ───────────────────────────
      final aliceIk1 = await newAliceIdentity();
      final r1 = await X3dhService.initiatorHandshake(
        ikADh: aliceIk1,
        bundleB: publishedBundle,
        preferredOpkId: 1,
      );
      expect(r1.opkId, equals(1));

      final sk1 = await X3dhService.responderHandshake(
        ikBDh: bobIdentity.ikDhKeyPair!,
        spkB: bobSpk,
        opkB: bobIdentity.getOpk(1),
        ekAPub: r1.ekPub,
        ikADhPub: (await aliceIk1.extractPublicKey()).bytes,
      );
      expect(sk1.length, equals(32));

      final aliceSess1 = await DoubleRatchetSession.initAlice(
        conversationId: 'hs_conv_1',
        peerIdentityPublicKeyB64: 'BOB=',
        sk: r1.sharedSecret,
        bobSpkPub: publishedBundle.spkPub,
      );
      final bobSess1 = await DoubleRatchetSession.initBob(
        conversationId: 'hs_conv_1',
        peerIdentityPublicKeyB64: 'ALICE1=',
        sk: Uint8List.fromList(sk1),
        spkBDh: bobSpk,
      );
      final w1 = await aliceSess1.encrypt('first handshake');
      expect(await bobSess1.decrypt(w1), equals('first handshake'));

      // Consume OPK 1 after authenticated success (receiver-side invariant).
      await bobIdentity.consumeOpk(1);

      // ── Handshake 2 (Alice₂, SAME published bundle, pool OPK id 2) ───────
      final aliceIk2 = await newAliceIdentity();
      final sameBundleAgain = PreKeyBundle.fromJson(jsonDecode(publishedBundleJson));
      final r2 = await X3dhService.initiatorHandshake(
        ikADh: aliceIk2,
        bundleB: sameBundleAgain,
        preferredOpkId: 2,
      );
      expect(r2.opkId, equals(2));

      final sk2 = await X3dhService.responderHandshake(
        ikBDh: bobIdentity.ikDhKeyPair!,
        spkB: bobSpk,
        opkB: bobIdentity.getOpk(2),
        ekAPub: r2.ekPub,
        ikADhPub: (await aliceIk2.extractPublicKey()).bytes,
      );
      expect(sk2.length, equals(32));

      final aliceSess2 = await DoubleRatchetSession.initAlice(
        conversationId: 'hs_conv_2',
        peerIdentityPublicKeyB64: 'BOB=',
        sk: r2.sharedSecret,
        bobSpkPub: publishedBundle.spkPub,
      );
      final bobSess2 = await DoubleRatchetSession.initBob(
        conversationId: 'hs_conv_2',
        peerIdentityPublicKeyB64: 'ALICE2=',
        sk: Uint8List.fromList(sk2),
        spkBDh: bobSpk,
      );
      final w2 = await aliceSess2.encrypt('second handshake');
      expect(await bobSess2.decrypt(w2), equals('second handshake'),
          reason: 'second offline handshake against the SAME published bundle must succeed');

      // ── Consumed-OPK reuse is rejected fail-closed ────────────────────────
      expect(
        () => bobIdentity.getOpk(1),
        throwsA(isA<X3dhException>()),
        reason: 'consumed OPK must never be usable again',
      );
      // Initiator-side selection of a consumed id still parses (the pool map
      // is a published artifact) — rejection happens receiver-side.
      final aliceIk3 = await newAliceIdentity();
      await expectLater(
        X3dhService.initiatorHandshake(
          ikADh: aliceIk3,
          bundleB: publishedBundle,
          preferredOpkId: 1,
        ),
        completes,
      );
      expect(
        () async => await X3dhService.responderHandshake(
          ikBDh: bobIdentity.ikDhKeyPair!,
          spkB: bobSpk,
          opkB: bobIdentity.getOpk(1), // consumed → throws
          ekAPub: r1.ekPub,
          ikADhPub: (await aliceIk1.extractPublicKey()).bytes,
        ),
        throwsA(isA<X3dhException>()),
      );
    });

    test('pool replenishes back to kOpkPoolSize after consumption', () async {
      await bobIdentity.consumeOpk(1);
      final refreshed = await bobIdentity.generatePreKeyBundleAsync();
      expect(refreshed!.opks.length, equals(kOpkPoolSize));
      expect(refreshed.opks.containsKey(1), isFalse,
          reason: 'consumed id must leave the published pool');
    });

    test('SessionManager-level handshake against a pool bundle succeeds end-to-end', () async {
      final aliceIdentity = IdentityKeyService.isolated();
      await aliceIdentity.init();

      final aliceMgr = SessionManager.isolated(identityService: aliceIdentity);
      final bobMgr   = SessionManager.isolated(identityService: bobIdentity);

      final wire = await aliceMgr.encryptV4('smoke_conv', 'pool smoke test',
          peerPreKeyBundleJson: publishedBundleJson);
      expect(await bobMgr.decryptV4('smoke_conv', wire), equals('pool smoke test'));
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // TEST 7 — QR handshake payload length bound
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2.4 — QR payload size', () {
    test('full v3 handshake payload with 8-OPK pool stays within QR-safe bound', () async {
      final identity = IdentityKeyService.isolated();
      await identity.init();

      // Realistic 516-char I2P destination key.
      final dest = base64Encode(Uint8List(384)); // 384 bytes → 512 b64 chars + padding
      final payload = await identity.generateHandshakePayloadAsync(dest);

      print('QR handshake payload length: ${payload.length} chars');
      expect(payload.length, lessThanOrEqualTo(1500),
          reason: 'payload must remain scannable by mobile QR readers');

      // Pool survives parse → persist → parse round-trip.
      final parsed = identity.parseHandshakePayload(payload);
      expect(parsed['preKeyBundle'], isNotEmpty);
      final reparsed = PreKeyBundle.fromJson(
        jsonDecode(parsed['preKeyBundle']!) as Map<String, dynamic>,
      );
      expect(reparsed.opks.length, equals(kOpkPoolSize));
    });
  });
}
