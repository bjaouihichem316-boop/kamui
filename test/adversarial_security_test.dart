// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/models/message.dart';
import 'package:kamui/services/crypto_service.dart';
import 'package:kamui/services/double_ratchet.dart';
import 'package:kamui/services/identity_key_service.dart';
import 'package:kamui/services/x3dh_service.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Kamui Adversarial Security & Invariants Test Suite (Phases 2, 4, 5, 6, 7)
// ══════════════════════════════════════════════════════════════════════════════

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    CryptoService().resetForTesting();
    IdentityKeyService().resetForTesting();
  });
  const convId = 'adv-conv-1';
  const peerB64 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

  final ed25519 = Ed25519();
  final x25519  = X25519();

  /// Helper to build genuine Bob node with OPK
  Future<({
    SimpleKeyPair ikEd,
    SimpleKeyPair ikDh,
    SimpleKeyPair spk,
    SimpleKeyPair opk,
    PreKeyBundle bundle,
  })> buildBobNode({int opkId = 1, bool includeOpk = true}) async {
    final ikEd = await ed25519.newKeyPair();
    final ikDh = await x25519.newKeyPair();
    final spk  = await x25519.newKeyPair();
    final opk  = await x25519.newKeyPair();

    final ikEdPub = await ikEd.extractPublicKey();
    final ikDhPub = await ikDh.extractPublicKey();
    final spkPub  = await spk.extractPublicKey();
    final opkPub  = await opk.extractPublicKey();

    final spkSig = await ed25519.sign(spkPub.bytes, keyPair: ikEd);

    final bundle = PreKeyBundle(
      ikPubEd: ikEdPub.bytes,
      ikPubDh: ikDhPub.bytes,
      spkPub:  spkPub.bytes,
      spkSig:  spkSig.bytes,
      opkId:   includeOpk ? opkId : null,
      opkPub:  includeOpk ? opkPub.bytes : null,
    );

    return (ikEd: ikEd, ikDh: ikDh, spk: spk, opk: opk, bundle: bundle);
  }

  /// Helper to establish Alice & Bob Double Ratchet pair
  Future<({
    DoubleRatchetSession aliceSession,
    DoubleRatchetSession bobSession,
    X3dhResult aliceX3dh,
  })> setupSessionPair({bool includeOpk = true}) async {
    final bobNode = await buildBobNode(includeOpk: includeOpk);
    final aliceIkDh = await x25519.newKeyPair();
    final aliceIkDhPub = await aliceIkDh.extractPublicKey();

    final aliceX3dh = await X3dhService.initiatorHandshake(
      ikADh: aliceIkDh,
      bundleB: bobNode.bundle,
    );

    final aliceSession = await DoubleRatchetSession.initAlice(
      conversationId: convId,
      peerIdentityPublicKeyB64: peerB64,
      sk: aliceX3dh.sharedSecret,
      bobSpkPub: bobNode.bundle.spkPub,
    );

    final bobX3dhSk = await X3dhService.responderHandshake(
      ikBDh: bobNode.ikDh,
      spkB:  bobNode.spk,
      opkB:  includeOpk ? bobNode.opk : null,
      ekAPub: aliceX3dh.ekPub,
      ikADhPub: aliceIkDhPub.bytes,
    );

    final bobSession = await DoubleRatchetSession.initBob(
      conversationId: convId,
      peerIdentityPublicKeyB64: peerB64,
      sk: bobX3dhSk,
      spkBDh: bobNode.spk,
    );

    return (aliceSession: aliceSession, bobSession: bobSession, aliceX3dh: aliceX3dh);
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PHASE 2: STORAGE REGRESSION INVARIANT TEST
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 2 — Message Decryption & Storage Encryption Invariant', () {
    test('Received wire payload is decrypted to plaintext and encrypted at rest with local AES', () async {
      final crypto = CryptoService();
      await crypto.init();

      final pair = await setupSessionPair();
      const secretPlaintext = 'TOP_SECRET_AIR_GAP_PAYLOAD_9941';

      // 1. Alice encrypts to wire payload
      final wirePayload = await pair.aliceSession.encrypt(secretPlaintext);
      expect(wirePayload.startsWith('kamui_v4:'), isTrue);

      // 2. Bob decrypts payload
      final decryptedText = await pair.bobSession.decrypt(wirePayload);
      expect(decryptedText, equals(secretPlaintext));

      // 3. Message model created with decrypted plaintext
      final msg = Message(
        id:             'test_msg_sec_1',
        conversationId: convId,
        text:           decryptedText,
        timestamp:      DateTime.now(),
        isSent:         false,
        isEncrypted:    true,
      );

      // 4. Encrypt for SQLite persistence (MessageRepositoryImpl behavior)
      final encryptedAtRest = crypto.encrypt(msg.text);

      // Invariant: Raw stored string must NOT contain the plaintext
      expect(encryptedAtRest.contains(secretPlaintext), isFalse,
          reason: 'Raw database column value must never contain plaintext');

      // Invariant: Decrypting stored value with local storage key recovers readable text for UI
      final recoveredStoredText = crypto.decrypt(encryptedAtRest);
      expect(recoveredStoredText, equals(secretPlaintext),
          reason: 'Local database storage must decrypt to readable plaintext');
      expect(msg.displayText, equals(secretPlaintext));
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // PHASE 4: ONE-TIME PREKEY (OPK) LIFECYCLE TESTS
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 4 — OPK Identification & Lifecycle', () {
    test('1. Valid OPK Handshake derives identical secrets & includes opkId', () async {
      final pair = await setupSessionPair(includeOpk: true);
      expect(pair.aliceX3dh.opkId, equals(1));
      final wire = await pair.aliceSession.encrypt('Test OPK 1');
      final plain = await pair.bobSession.decrypt(wire);
      expect(plain, equals('Test OPK 1'));
    });

    test('2. OPK Single-use Consumption and Replay Rejection in IdentityKeyService', () async {
      final service = IdentityKeyService();
      await service.init();

      final opk1Id = service.currentOpkId;
      expect(opk1Id, isNotNull);

      // Look up OPK before consumption
      final opkKp = service.getOpk(opk1Id!);
      expect(opkKp, isNotNull);

      // Consume OPK after successful authenticated handshake
      await service.consumeOpk(opk1Id);

      // Reusing already-consumed OPK MUST throw X3dhException
      expect(
        () => service.getOpk(opk1Id),
        throwsA(isA<X3dhException>()),
        reason: 'Consumed OPK must be rejected on replay',
      );

      // Service replenishes with fresh OPK with incremented ID
      expect(service.currentOpkId, isNotNull);
      expect(service.currentOpkId, isNot(equals(opk1Id)));
    });

    test('3. Invalid OPK ID throws X3dhException and does not corrupt state', () async {
      final service = IdentityKeyService();
      await service.init();

      expect(
        () => service.getOpk(999999),
        throwsA(isA<X3dhException>()),
        reason: 'Unknown OPK ID must throw X3dhException',
      );
    });

    test('4. Failed handshake does NOT consume OPK', () async {
      final service = IdentityKeyService();
      await service.init();
      final currentId = service.currentOpkId!;

      // Attempt handshake with tampered bundle
      final bobNode = await buildBobNode(opkId: currentId, includeOpk: true);
      final tamperedBundle = PreKeyBundle(
        ikPubEd: bobNode.bundle.ikPubEd,
        ikPubDh: bobNode.bundle.ikPubDh,
        spkPub:  bobNode.bundle.spkPub,
        spkSig:  Uint8List(64), // Invalid signature!
        opkId:   currentId,
        opkPub:  bobNode.bundle.opkPub,
      );

      final aliceIkDh = await x25519.newKeyPair();
      expect(
        () async => await X3dhService.initiatorHandshake(ikADh: aliceIkDh, bundleB: tamperedBundle),
        throwsA(isA<X3dhException>()),
      );

      // The OPK in service must still be available (not consumed)
      expect(service.getOpk(currentId), isNotNull);
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // PHASE 7: ADVERSARIAL RATCHET TESTS (10 CRITICAL INVARIANTS)
  // ════════════════════════════════════════════════════════════════════════════
  group('Phase 7 — Adversarial Ratchet Test Suite (10 Security Invariants)', () {
    // TEST 1: Alice sends 100 messages in order -> Bob receives and decrypts all
    test('TEST 1: 100 in-order messages all decrypt correctly', () async {
      final pair = await setupSessionPair();
      for (int i = 0; i < 100; i++) {
        final plain = 'Message #$i from Alice';
        final wire  = await pair.aliceSession.encrypt(plain);
        final dec   = await pair.bobSession.decrypt(wire);
        expect(dec, equals(plain));
      }
    });

    // TEST 2: Out of order messages: 0, 5, 2, 4, 1, 3
    test('TEST 2: Out-of-order sequence (0, 5, 2, 4, 1, 3) all decrypt correctly', () async {
      final pair = await setupSessionPair();
      final wires = <int, String>{};
      for (int i = 0; i <= 5; i++) {
        wires[i] = await pair.aliceSession.encrypt('Order Test Msg $i');
      }

      // Delivery order: 0, 5, 2, 4, 1, 3
      expect(await pair.bobSession.decrypt(wires[0]!), equals('Order Test Msg 0'));
      expect(await pair.bobSession.decrypt(wires[5]!), equals('Order Test Msg 5'));
      expect(await pair.bobSession.decrypt(wires[2]!), equals('Order Test Msg 2'));
      expect(await pair.bobSession.decrypt(wires[4]!), equals('Order Test Msg 4'));
      expect(await pair.bobSession.decrypt(wires[1]!), equals('Order Test Msg 1'));
      expect(await pair.bobSession.decrypt(wires[3]!), equals('Order Test Msg 3'));
    });

    // TEST 3: Replay a previously accepted message -> must be rejected
    test('TEST 3: Replaying a previously accepted message is rejected (Fail-Closed)', () async {
      final pair = await setupSessionPair();
      final wire = await pair.aliceSession.encrypt('Replay Target');
      await pair.bobSession.decrypt(wire);

      // Replay attack
      expect(
        () async => await pair.bobSession.decrypt(wire),
        throwsA(isA<RatchetException>()),
        reason: 'Replayed message must throw RatchetException',
      );
    });

    // TEST 4: Modify ciphertext -> MAC fails, ratchet state remains valid
    test('TEST 4: Tampered ciphertext fails MAC and preserves valid ratchet state', () async {
      final pair = await setupSessionPair();
      final wire1 = await pair.aliceSession.encrypt('Valid 1');
      final wire2 = await pair.aliceSession.encrypt('Valid 2');

      // Tamper with wire1 ciphertext
      final parts = wire1.split(':');
      final badCt = base64Encode(Uint8List.fromList([...base64Decode(parts[3]).sublist(0, 10), 0xFF, 0xFF]));
      final tamperedWire = '${parts[0]}:${parts[1]}:${parts[2]}:$badCt';

      expect(
        () async => await pair.bobSession.decrypt(tamperedWire),
        throwsA(isA<RatchetException>()),
      );

      // State is preserved: subsequent valid wire2 decrypts cleanly
      expect(await pair.bobSession.decrypt(wire2), equals('Valid 2'));
    });

    // TEST 5: Modify message counter n -> authentication fails, state remains valid
    test('TEST 5: Modified message counter n fails authentication and preserves state', () async {
      final pair = await setupSessionPair();
      final wire = await pair.aliceSession.encrypt('Test Counter');
      final parts = wire.split(':');

      // Parse header and tamper with n
      final header = RatchetHeader.fromBase64(parts[1]);
      final badHeader = RatchetHeader(dhPub: header.dhPub, n: header.n + 10, pn: header.pn);
      final tamperedWire = '${parts[0]}:${badHeader.toBase64()}:${parts[2]}:${parts[3]}';

      expect(
        () async => await pair.bobSession.decrypt(tamperedWire),
        throwsA(isA<RatchetException>()),
      );

      // Original uncorrupted wire still decrypts cleanly
      expect(await pair.bobSession.decrypt(wire), equals('Test Counter'));
    });

    // TEST 6: Modify previous counter pn -> authentication fails, state remains valid
    test('TEST 6: Modified pn in header fails authentication and preserves state', () async {
      final pair = await setupSessionPair();
      final wire = await pair.aliceSession.encrypt('Test PN');
      final parts = wire.split(':');

      final header = RatchetHeader.fromBase64(parts[1]);
      final badHeader = RatchetHeader(dhPub: header.dhPub, n: header.n, pn: 99);
      final tamperedWire = '${parts[0]}:${badHeader.toBase64()}:${parts[2]}:${parts[3]}';

      expect(
        () async => await pair.bobSession.decrypt(tamperedWire),
        throwsA(isA<RatchetException>()),
      );

      // Original uncorrupted wire still decrypts cleanly
      expect(await pair.bobSession.decrypt(wire), equals('Test PN'));
    });

    // TEST 7: Send a fake new DH public key with invalid ciphertext -> candidate state rollback
    test('TEST 7: Fake DH public key with invalid ciphertext triggers complete state rollback', () async {
      final pair = await setupSessionPair();
      final fakeKp = await x25519.newKeyPair();
      final fakePub = await fakeKp.extractPublicKey();

      final badHeader = RatchetHeader(dhPub: fakePub.bytes, n: 0, pn: 0);
      final fakeWire = 'kamui_v4:${badHeader.toBase64()}:${base64Encode(Uint8List(12))}:${base64Encode(Uint8List(32))}';

      expect(
        () async => await pair.bobSession.decrypt(fakeWire),
        throwsA(isA<RatchetException>()),
      );

      // Valid Alice message must still decrypt without desynchronization
      final genuineWire = await pair.aliceSession.encrypt('Genuine after fake DH');
      expect(await pair.bobSession.decrypt(genuineWire), equals('Genuine after fake DH'));
    });

    // TEST 8: Multiple DH ratchet transitions in both directions
    test('TEST 8: Multiple DH ratchet transitions in both directions', () async {
      final pair = await setupSessionPair();

      // Alice -> Bob (DH 1)
      final w1 = await pair.aliceSession.encrypt('A1');
      expect(await pair.bobSession.decrypt(w1), equals('A1'));

      // Bob -> Alice (DH 2)
      final w2 = await pair.bobSession.encrypt('B1');
      expect(await pair.aliceSession.decrypt(w2), equals('B1'));

      // Alice -> Bob (DH 3)
      final w3 = await pair.aliceSession.encrypt('A2');
      expect(await pair.bobSession.decrypt(w3), equals('A2'));

      // Bob -> Alice (DH 4)
      final w4 = await pair.bobSession.encrypt('B2');
      expect(await pair.aliceSession.decrypt(w4), equals('B2'));
    });

    // TEST 9: Multi-turn bidirectional exchange with many messages per turn
    test('TEST 9: Multi-turn bidirectional exchange with bursts of messages', () async {
      final pair = await setupSessionPair();

      // Turn 1: Alice sends 5
      for (int i = 0; i < 5; i++) {
        final w = await pair.aliceSession.encrypt('Alice turn 1 msg $i');
        expect(await pair.bobSession.decrypt(w), equals('Alice turn 1 msg $i'));
      }

      // Turn 2: Bob sends 5
      for (int i = 0; i < 5; i++) {
        final w = await pair.bobSession.encrypt('Bob turn 2 msg $i');
        expect(await pair.aliceSession.decrypt(w), equals('Bob turn 2 msg $i'));
      }

      // Turn 3: Alice sends 5
      for (int i = 0; i < 5; i++) {
        final w = await pair.aliceSession.encrypt('Alice turn 3 msg $i');
        expect(await pair.bobSession.decrypt(w), equals('Alice turn 3 msg $i'));
      }
    });

    // TEST 10: Lost messages + later delivery of valid skipped messages
    test('TEST 10: Lost messages with gaps + late delivery of skipped messages', () async {
      final pair = await setupSessionPair();

      final m0 = await pair.aliceSession.encrypt('M0');
      final m1 = await pair.aliceSession.encrypt('M1'); // Lost
      final m2 = await pair.aliceSession.encrypt('M2'); // Lost
      final m3 = await pair.aliceSession.encrypt('M3');

      // Bob receives M0 and M3
      expect(await pair.bobSession.decrypt(m0), equals('M0'));
      expect(await pair.bobSession.decrypt(m3), equals('M3'));

      // Bob later receives delayed M2 and M1
      expect(await pair.bobSession.decrypt(m2), equals('M2'));
      expect(await pair.bobSession.decrypt(m1), equals('M1'));

      // Replaying M1 now fails
      expect(
        () async => await pair.bobSession.decrypt(m1),
        throwsA(isA<RatchetException>()),
      );
    });
  });
}
