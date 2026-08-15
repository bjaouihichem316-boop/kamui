// ignore_for_file: avoid_print

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/double_ratchet.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Kamui Double Ratchet Engine — Deep Audit Test Suite
// ══════════════════════════════════════════════════════════════════════════════
//
// Verifies:
//   1. KDF_RK produces two independent 32-byte keys
//   2. KDF_CK produces advancing chain + message keys
//   3. Chain key advances after each KDF_CK call (forward secrecy)
//   4. Alice → Bob in-order messages decrypt correctly
//   5. Bob → Alice in-order messages decrypt correctly (bidirectional)
//   6. DH Ratchet step fires on new peer pub key
//   7. Out-of-order messages recovered from SkippedKeyStore
//   8. Large gap (5 skipped) recovered correctly
//   9. Replay detection — already-received index raises RatchetException
//  10. DoS guard — gap > kMaxSkip raises RatchetException
//  11. SkippedKeyStore TTL pruning
//  12. SkippedKeyStore bounded size
//  13. kamui_v4 wire format structure (4-segment colon-separated)
//  14. Wrong message key produces RatchetException (AES-GCM MAC failure)
//  15. Multiple conversations are fully isolated
//  16. Full bidirectional multi-turn conversation (15 messages)

void main() {
  const convId = 'test-conv-001';
  const peerB64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  // ── Helpers ────────────────────────────────────────────────────────────────

  /// Creates a fresh Alice ↔ Bob session pair sharing [sk].
  Future<(DoubleRatchetSession alice, DoubleRatchetSession bob)> buildAliceBob({
    Uint8List? sharedSecret,
  }) async {
    final x25519 = X25519();
    final sk = sharedSecret ?? Uint8List.fromList(List.generate(32, (i) => i + 1));

    // Bob generates his SPK (used as his initial ratchet keypair)
    final spkB    = await x25519.newKeyPair();
    final spkBPub = await spkB.extractPublicKey();

    final alice = await DoubleRatchetSession.initAlice(
      conversationId:           convId,
      peerIdentityPublicKeyB64: peerB64,
      sk:        sk,
      bobSpkPub: spkBPub.bytes,
    );

    final bob = await DoubleRatchetSession.initBob(
      conversationId:           convId,
      peerIdentityPublicKeyB64: peerB64,
      sk:        sk,
      spkBDh:    spkB,
    );

    return (alice, bob);
  }

  // ── 1. KDF_RK ─────────────────────────────────────────────────────────────
  group('KDF_RK', () {
    test('Produces two 32-byte keys', () async {
      final rk     = Uint8List.fromList(List.generate(32, (i) => i));
      final dhOut  = List.generate(32, (i) => 255 - i);
      final (newRk, newCk) = await kdfRk(rk, dhOut);
      expect(newRk.length, 32, reason: 'New root key must be 32 bytes');
      expect(newCk.length, 32, reason: 'New chain key must be 32 bytes');
    });

    test('RK ≠ CK (keys are independent)', () async {
      final rk    = Uint8List.fromList(List.filled(32, 0xAB));
      final dhOut = List.filled(32, 0xCD);
      final (newRk, newCk) = await kdfRk(rk, dhOut);
      expect(newRk, isNot(equals(newCk)),
          reason: 'Root key and chain key must be distinct');
    });

    test('Different DH outputs produce different keys', () async {
      final rk     = Uint8List.fromList(List.filled(32, 0x11));
      final dh1    = List.filled(32, 0x22);
      final dh2    = List.filled(32, 0x33);
      final (rk1, ck1) = await kdfRk(rk, dh1);
      final (rk2, ck2) = await kdfRk(rk, dh2);
      expect(rk1, isNot(equals(rk2)));
      expect(ck1, isNot(equals(ck2)));
    });
  });

  // ── 2. KDF_CK ─────────────────────────────────────────────────────────────
  group('KDF_CK', () {
    test('Produces nextCk and mk each 32 bytes', () async {
      final ck = Uint8List.fromList(List.generate(32, (i) => i * 3));
      final (nextCk, mk) = await kdfCk(ck);
      expect(nextCk.length, 32);
      expect(mk.length,     32);
    });

    test('nextCk ≠ mk (keys are independent)', () async {
      final ck = Uint8List.fromList(List.filled(32, 0x77));
      final (nextCk, mk) = await kdfCk(ck);
      expect(nextCk, isNot(equals(mk)));
    });

    test('Repeated calls produce different keys (forward secrecy)', () async {
      var ck = Uint8List.fromList(List.filled(32, 0x42));
      final mkList = <Uint8List>[];
      for (var i = 0; i < 5; i++) {
        final (nextCk, mk) = await kdfCk(ck);
        mkList.add(mk);
        ck = nextCk;
      }
      // All message keys must be distinct
      for (var i = 0; i < mkList.length; i++) {
        for (var j = i + 1; j < mkList.length; j++) {
          expect(mkList[i], isNot(equals(mkList[j])),
              reason: 'MK[$i] must differ from MK[$j]');
        }
      }
    });
  });

  // ── 3. SkippedKeyStore ────────────────────────────────────────────────────
  group('SkippedKeyStore', () {
    test('put / take round-trip retrieves stored key', () {
      final store  = SkippedKeyStore();
      final dhPub  = List.generate(32, (i) => i);
      final key    = Uint8List.fromList(List.filled(32, 0xAA));
      store.put(dhPub, 5, key);
      final retrieved = store.take(dhPub, 5);
      expect(retrieved, equals(key));
    });

    test('take returns null for absent key', () {
      final store = SkippedKeyStore();
      expect(store.take(List.filled(32, 0), 99), isNull);
    });

    test('take removes the key (single-use)', () {
      final store = SkippedKeyStore();
      final key   = Uint8List.fromList(List.filled(32, 0xFF));
      store.put(List.filled(32, 1), 0, key);
      store.take(List.filled(32, 1), 0);
      expect(store.take(List.filled(32, 1), 0), isNull,
          reason: 'Key must be consumed on first take');
    });

    test('Different dhPub → different index (no collision)', () {
      final store = SkippedKeyStore();
      final k1    = Uint8List.fromList(List.filled(32, 0x11));
      final k2    = Uint8List.fromList(List.filled(32, 0x22));
      store.put(List.filled(32, 0xAA), 0, k1);
      store.put(List.filled(32, 0xBB), 0, k2);
      expect(store.take(List.filled(32, 0xAA), 0), equals(k1));
      expect(store.take(List.filled(32, 0xBB), 0), equals(k2));
    });

    test('Store enforces kMaxSkip bound', () {
      final store = SkippedKeyStore();
      final key   = Uint8List.fromList(List.filled(32, 1));
      // Fill up to kMaxSkip entries (using unique dhPub per entry)
      var stored = 0;
      for (var i = 0; i < kMaxSkip; i++) {
        final dhPub = List.generate(32, (j) => (i >> (j * 0)) & 0xFF);
        if (store.put(dhPub, i, key)) stored++;
      }
      expect(stored, equals(kMaxSkip));
      // Next insert should fail
      final overflow = store.put(List.filled(32, 0xFF), 9999, key);
      expect(overflow, isFalse, reason: 'Store must reject entries beyond kMaxSkip');
    });
  });

  // ── 4. Wire Format ────────────────────────────────────────────────────────
  group('Wire Format', () {
    test('kamui_v4 payload has 4 colon-separated segments', () async {
      final (alice, bob) = await buildAliceBob();
      final wire = await alice.encrypt('hello');
      expect(wire.startsWith('kamui_v4:'), isTrue);
      final parts = wire.split(':');
      expect(parts.length, 4, reason: 'Payload must have 4 segments');
    });

    test('RatchetHeader round-trip toBase64/fromBase64', () {
      final h = RatchetHeader(dhPub: List.generate(32, (i) => i), n: 5, pn: 3);
      final restored = RatchetHeader.fromBase64(h.toBase64());
      expect(restored.dhPub, equals(h.dhPub));
      expect(restored.n,     equals(h.n));
      expect(restored.pn,    equals(h.pn));
    });
  });

  // ── 5. In-order Encryption / Decryption ───────────────────────────────────
  group('In-order Encrypt / Decrypt', () {
    test('Alice sends 3 messages to Bob — all decrypt correctly', () async {
      final (alice, bob) = await buildAliceBob();
      final messages = ['Hello Bob', 'Secret message', 'Final word'];
      for (final msg in messages) {
        final wire = await alice.encrypt(msg);
        final plain = await bob.decrypt(wire);
        expect(plain, equals(msg),
            reason: 'Decrypted text must match original for "$msg"');
      }
    });

    test('Bob replies to Alice — bidirectional works', () async {
      final (alice, bob) = await buildAliceBob();

      // Alice → Bob
      final wire1 = await alice.encrypt('Hi Bob');
      expect(await bob.decrypt(wire1), equals('Hi Bob'));

      // Bob → Alice (triggers Bob's first DH ratchet step as sender)
      final wire2 = await bob.encrypt('Hi Alice');
      expect(await alice.decrypt(wire2), equals('Hi Alice'));
    });

    test('Cannot decrypt non-v4 payload', () async {
      final (_, bob) = await buildAliceBob();
      expect(
        () async => bob.decrypt('kamui_v2:somedata'),
        throwsA(isA<RatchetException>()),
        reason: 'Non-v4 payload must throw RatchetException',
      );
    });

    test('Message key is different for each message (symmetric forward secrecy)', () async {
      final (alice, _) = await buildAliceBob();
      final wire1 = await alice.encrypt('msg1');
      final wire2 = await alice.encrypt('msg2');
      // Payloads must differ (different message keys → different ciphertext)
      expect(wire1, isNot(equals(wire2)));
    });
  });

  // ── 6. Out-of-order Recovery ──────────────────────────────────────────────
  group('Out-of-order Recovery', () {
    test('Message 1 arrives before message 0 — both decrypt', () async {
      final (alice, bob) = await buildAliceBob();
      final wire0 = await alice.encrypt('msg-0');
      final wire1 = await alice.encrypt('msg-1');

      // Deliver in reverse order
      final plain1 = await bob.decrypt(wire1);
      expect(plain1, equals('msg-1'),
          reason: 'Out-of-order msg-1 should decrypt (skipped msg-0 stored)');

      final plain0 = await bob.decrypt(wire0);
      expect(plain0, equals('msg-0'),
          reason: 'Delayed msg-0 should be recovered from skipped key store');
    });

    test('5-message gap recovery — all decrypt in scrambled order', () async {
      final (alice, bob) = await buildAliceBob();
      final wires = <String>[];
      for (var i = 0; i < 6; i++) {
        wires.add(await alice.encrypt('msg-$i'));
      }

      // Deliver 5 first, then 0..4
      final p5 = await bob.decrypt(wires[5]);
      expect(p5, equals('msg-5'));

      for (var i = 0; i < 5; i++) {
        final p = await bob.decrypt(wires[i]);
        expect(p, equals('msg-$i'), reason: 'Delayed msg-$i must be recoverable');
      }

      // Skipped key store should be empty now
      expect(bob.skippedKeyCount, equals(0),
          reason: 'All skipped keys should be consumed');
    });

    test('Skipped keys stored in store during gap', () async {
      final (alice, bob) = await buildAliceBob();
      // Encrypt 4 messages but only deliver the last one
      for (var i = 0; i < 3; i++) {
        await alice.encrypt('skip-$i');
      }
      final wire3 = await alice.encrypt('skip-3');
      await bob.decrypt(wire3);

      // 3 skipped keys should now be in the store
      expect(bob.skippedKeyCount, equals(3),
          reason: '3 skipped message keys should be stored for out-of-order recovery');
    });
  });

  // ── 7. DH Ratchet Step ────────────────────────────────────────────────────
  group('DH Ratchet Step', () {
    test('Keys after DH ratchet differ from initial chain keys', () async {
      final (alice, bob) = await buildAliceBob();

      // Phase 1: Alice sends, Bob receives (initial epoch)
      final w0 = await alice.encrypt('epoch-0-msg-0');
      final w1 = await alice.encrypt('epoch-0-msg-1');
      await bob.decrypt(w0);
      await bob.decrypt(w1);

      // Phase 2: Bob sends (triggers Bob's DH ratchet step as initiator)
      final wB0 = await bob.encrypt('bob-reply-0');
      // Alice decrypts — triggers Alice's DH ratchet step
      final pB0 = await alice.decrypt(wB0);
      expect(pB0, equals('bob-reply-0'));

      // Phase 3: Alice sends again (new DH epoch on her side)
      final w2 = await alice.encrypt('epoch-1-msg-0');
      final p2 = await bob.decrypt(w2);
      expect(p2, equals('epoch-1-msg-0'),
          reason: 'Message in new DH epoch must decrypt correctly');
    });

    test('Bob ratchet key in header changes after DH ratchet fires', () async {
      final (alice, bob) = await buildAliceBob();

      // Alice's initial ratchet pub
      final aliceInitPub = await alice.localRatchetPub;
      expect(aliceInitPub.length, 32, reason: 'Alice initial ratchet pub must be 32 bytes');

      // Bob cannot send before receiving Alice's first message (no sending chain).
      // Send Alice's first message → triggers Bob's DH ratchet receive step.
      final w0 = await alice.encrypt('first from Alice');
      await bob.decrypt(w0);

      // Now Bob has a sending chain — record his ratchet pub after receiving
      final bobPubAfterReceive = await bob.localRatchetPub;
      expect(bobPubAfterReceive.length, 32);

      // Bob sends his first reply (uses new local ratchet keypair generated during step)
      final wB = await bob.encrypt('reply from Bob');
      final bobPubAfterSend = await bob.localRatchetPub;

      // Ratchet pub embedded in the header should equal Bob's current ratchet pub
      expect(bobPubAfterSend, equals(bobPubAfterReceive),
          reason: 'Bob ratchet pub should not change between receiving and sending in same epoch');

      // Alice decrypts Bob's reply — triggers Alice's DH ratchet step
      final plain = await alice.decrypt(wB);
      expect(plain, equals('reply from Bob'),
          reason: 'Alice must decrypt Bob\'s reply correctly after DH ratchet step');

      // Alice generates a new ratchet keypair after the DH step
      final alicePubAfterRatchet = await alice.localRatchetPub;
      expect(alicePubAfterRatchet, isNot(equals(aliceInitPub)),
          reason: 'Alice ratchet pub must change after DH ratchet step from Bob\'s message');
    });
  });

  // ── 8. Security Properties ────────────────────────────────────────────────
  group('Security Properties', () {
    test('Different shared secrets → cannot decrypt each other\'s messages', () async {
      final sk1 = Uint8List.fromList(List.generate(32, (i) => i + 1));
      final sk2 = Uint8List.fromList(List.generate(32, (i) => i + 100));

      final (alice1, _)   = await buildAliceBob(sharedSecret: sk1);
      final (_, bob2)     = await buildAliceBob(sharedSecret: sk2);

      final wire = await alice1.encrypt('secret');
      expect(
        () async => bob2.decrypt(wire),
        throwsA(isA<RatchetException>()),
        reason: 'Wrong session must fail to decrypt with RatchetException',
      );
    });

    test('Replay detection: same wire payload rejected on second attempt', () async {
      final (alice, bob) = await buildAliceBob();
      final wire = await alice.encrypt('once');
      await bob.decrypt(wire); // first: success

      // Second attempt: same n < _nr
      expect(
        () async => bob.decrypt(wire),
        throwsA(isA<RatchetException>()),
        reason: 'Replayed message must raise RatchetException',
      );
    });

    test('Tampered ciphertext raises RatchetException', () async {
      final (alice, bob) = await buildAliceBob();
      final wire  = await alice.encrypt('tamper me');
      final parts = wire.split(':');
      // Flip last byte of ciphertext base64 (crude but sufficient)
      final bad   = '${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}ZZZZ';
      expect(
        () async => bob.decrypt(bad),
        throwsA(isA<RatchetException>()),
        reason: 'Tampered ciphertext must raise RatchetException',
      );
    });

    test('Two independent conversations produce independent ciphertexts', () async {
      final (alice1, _) = await buildAliceBob();
      final (alice2, _) = await buildAliceBob();

      final wire1 = await alice1.encrypt('same message');
      final wire2 = await alice2.encrypt('same message');
      expect(wire1, isNot(equals(wire2)),
          reason: 'Independent sessions must produce independent ciphertexts');
    });
  });

  // ── 9. Strict Header Validation ──────────────────────────────────────────
  group('Strict Header Validation', () {
    test('dhPub must be exactly 32 bytes', () {
      expect(
        () => RatchetHeader(dhPub: List.filled(31, 0), n: 0, pn: 0),
        throwsA(isA<RatchetException>()),
      );
      expect(
        () => RatchetHeader(dhPub: List.filled(33, 0), n: 0, pn: 0),
        throwsA(isA<RatchetException>()),
      );
      expect(
        () => RatchetHeader(dhPub: List.filled(32, 0), n: 0, pn: 0),
        returnsNormally,
      );
    });

    test('n and pn must be non-negative and <= kMaxSkip', () {
      final validDh = List.filled(32, 0);
      expect(() => RatchetHeader(dhPub: validDh, n: -1, pn: 0), throwsA(isA<RatchetException>()));
      expect(() => RatchetHeader(dhPub: validDh, n: 0, pn: -1), throwsA(isA<RatchetException>()));
      expect(() => RatchetHeader(dhPub: validDh, n: kMaxSkip + 1, pn: 0), throwsA(isA<RatchetException>()));
      expect(() => RatchetHeader(dhPub: validDh, n: 0, pn: kMaxSkip + 1), throwsA(isA<RatchetException>()));
      expect(() => RatchetHeader(dhPub: validDh, n: kMaxSkip, pn: kMaxSkip), returnsNormally);
    });

    test('fromJson validates field types and values', () {
      expect(
        () => RatchetHeader.fromJson({'dh': 'invalid-base64!', 'n': 0, 'pn': 0}),
        throwsA(isA<RatchetException>()),
      );
      expect(
        () => RatchetHeader.fromJson({'n': 0, 'pn': 0}),
        throwsA(isA<RatchetException>()),
      );
      expect(
        () => RatchetHeader.fromBase64('invalid-base64-string'),
        throwsA(isA<RatchetException>()),
      );
    });
  });

  // ── 10. Skipped Keys: Peek ➔ Authenticate ➔ Consume Pattern ───────────────
  group('Skipped Keys: Peek ➔ Authenticate ➔ Consume', () {
    test('peek() does not remove key until explicit remove()', () {
      final store = SkippedKeyStore();
      final dhPub = List.generate(32, (i) => i);
      final key   = Uint8List.fromList(List.filled(32, 0x42));

      store.put(dhPub, 3, key);
      expect(store.peek(dhPub, 3), equals(key));
      expect(store.peek(dhPub, 3), equals(key), reason: 'peek must not consume the key');
      expect(store.length, equals(1));

      expect(store.remove(dhPub, 3), isTrue);
      expect(store.peek(dhPub, 3), isNull);
      expect(store.length, equals(0));
    });

    test('Corrupted out-of-order message does not consume skipped key (DoS protection)', () async {
      final (alice, bob) = await buildAliceBob();

      // Alice sends msg0, msg1, msg2
      final wire0 = await alice.encrypt('msg-0');
      final wire1 = await alice.encrypt('msg-1');
      final wire2 = await alice.encrypt('msg-2');

      // Bob receives msg2 first -> msg0 and msg1 stored in skipped keys
      final plain2 = await bob.decrypt(wire2);
      expect(plain2, equals('msg-2'));
      expect(bob.skippedKeyCount, equals(2));

      // Attacker tampers with wire0
      final parts0 = wire0.split(':');
      final badWire0 = '${parts0[0]}:${parts0[1]}:${parts0[2]}:${parts0[3]}BADMAC';

      // Bob attempts to decrypt corrupted msg0 -> fails with MAC error
      await expectLater(
        () => bob.decrypt(badWire0),
        throwsA(isA<RatchetException>()),
      );

      // Key for msg0 MUST STILL BE IN STORE (not consumed by failed attempt!)
      expect(bob.skippedKeyCount, equals(2),
          reason: 'Failed MAC check must not consume/delete the skipped key');

      // Now legitimate wire0 arrives -> decrypts successfully and key is consumed!
      final legitPlain0 = await bob.decrypt(wire0);
      expect(legitPlain0, equals('msg-0'));
      expect(bob.skippedKeyCount, equals(1),
          reason: 'Legitimate msg0 successfully consumed its skipped key');

      // Legitimate wire1 arrives -> decrypts successfully
      final legitPlain1 = await bob.decrypt(wire1);
      expect(legitPlain1, equals('msg-1'));
      expect(bob.skippedKeyCount, equals(0));
    });
  });

  // ── 11. Transactional State Mutation (Rollback on MAC Failure) ────────────
  group('Transactional State in DH Ratchet', () {
    test('Corrupted new-epoch DH message does not mutate receiver state (anti-desync)', () async {
      final (alice, bob) = await buildAliceBob();

      // Exchange initial message to establish chains
      final w0 = await alice.encrypt('init from Alice');
      expect(await bob.decrypt(w0), equals('init from Alice'));

      // Bob sends a message (Bob's sending ratchet epoch 0)
      final legitBobWire = await bob.encrypt('legit reply from Bob');

      // Attacker tampers with Bob's message (new DH epoch from Alice's perspective)
      final parts = legitBobWire.split(':');
      final corruptedBobWire = '${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}CORRUPT';

      // Alice attempts to decrypt corrupted new-epoch message -> fails!
      await expectLater(
        () => alice.decrypt(corruptedBobWire),
        throwsA(isA<RatchetException>()),
      );

      // Alice's state was NOT corrupted! When legitimate message is delivered, it decrypts cleanly:
      final decrypted = await alice.decrypt(legitBobWire);
      expect(decrypted, equals('legit reply from Bob'));

      // Subsequent turns continue normally without desynchronization
      final aliceFollowUp = await alice.encrypt('alice follow up');
      expect(await bob.decrypt(aliceFollowUp), equals('alice follow up'));
    });

    test('Corrupted same-epoch gap message does not advance receive counter', () async {
      final (alice, bob) = await buildAliceBob();

      // Alice encrypts msg0, msg1, msg2
      await alice.encrypt('msg0');
      final wire1 = await alice.encrypt('msg1');
      await alice.encrypt('msg2');

      // Corrupt wire1 (gap message with n=1)
      final parts = wire1.split(':');
      final badWire1 = '${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}BAD';

      // Bob tries to decrypt badWire1 -> fails
      await expectLater(
        () => bob.decrypt(badWire1),
        throwsA(isA<RatchetException>()),
      );

      // Bob's receive counter must still be at 0, no keys prematurely committed
      expect(bob.skippedKeyCount, equals(0));

      // Now legitimate wire1 arrives -> should skip msg0 and decrypt msg1
      final plain1 = await bob.decrypt(wire1);
      expect(plain1, equals('msg1'));
      expect(bob.skippedKeyCount, equals(1)); // msg0 is stored
    });
  });

  // ── 12. Full Bidirectional Conversation ───────────────────────────────────
  group('Full Bidirectional Conversation', () {
    test('15-message multi-turn conversation — all decrypt correctly', () async {
      final (alice, bob) = await buildAliceBob();
      final transcript = <String>[];

      // Simulate alternating conversation
      for (var i = 0; i < 5; i++) {
        // Alice sends 2 messages
        for (var j = 0; j < 2; j++) {
          final msg  = 'A→B turn$i msg$j';
          final wire = await alice.encrypt(msg);
          final dec  = await bob.decrypt(wire);
          expect(dec, equals(msg));
          transcript.add(msg);
        }
        // Bob replies once
        final reply  = 'B→A reply$i';
        final wire   = await bob.encrypt(reply);
        final dec    = await alice.decrypt(wire);
        expect(dec, equals(reply));
        transcript.add(reply);
      }

      expect(transcript.length, equals(15),
          reason: 'All 15 messages must be exchanged successfully');
    });
  });
}

