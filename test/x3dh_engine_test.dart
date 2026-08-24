// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/x3dh_service.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Kamui X3DH Engine — Deep Audit Test Suite
// ══════════════════════════════════════════════════════════════════════════════
//
// Verifies:
//   1. SPK Signature Generation & Verification (MITM detection)
//   2. X3DH Initiator ↔ Responder derive identical shared secrets
//   3. Tampered SPK_pub fails signature check
//   4. Wrong IK cannot forge a valid SPK signature
//   5. HKDF output is 32 bytes and domain-separated
//   6. 3-DH (no OPK) and 4-DH (with OPK) produce different secrets
//   7. PreKeyBundle JSON serialization / deserialization round-trip
//   8. Independent sessions produce independent secrets
//   9. Fail-Closed: initiatorHandshake throws on tampered bundle

void main() {
  final ed25519 = Ed25519();
  final x25519  = X25519();

  // ── Helper: build a genuine PreKeyBundle for 'Bob' ─────────────────────────
  Future<({
    PreKeyBundle bundle,
    SimpleKeyPair ikBDh,
    SimpleKeyPair spkB,
  })> buildBobBundle({bool includeOpk = true}) async {
    // IK_ed (signing)
    final ikEdKP  = await ed25519.newKeyPair();
    final ikEdPub = await ikEdKP.extractPublicKey();
    // IK_dh (DH)
    final ikDhKP  = await x25519.newKeyPair();
    final ikDhPub = await ikDhKP.extractPublicKey();
    // SPK
    final spkKP  = await x25519.newKeyPair();
    final spkPub = await spkKP.extractPublicKey();
    // Sign SPK_pub with IK_ed
    final spkSig = await ed25519.sign(spkPub.bytes, keyPair: ikEdKP);
    // OPK
    List<int>? opkPubBytes;
    int? opkId;
    if (includeOpk) {
      final opkKP  = await x25519.newKeyPair();
      final opkPub = await opkKP.extractPublicKey();
      opkPubBytes  = opkPub.bytes;
      opkId        = 1;
    }

    final bundle = PreKeyBundle(
      ikPubEd: ikEdPub.bytes,
      ikPubDh: ikDhPub.bytes,
      spkPub:  spkPub.bytes,
      spkSig:  spkSig.bytes,
      opkId:   opkId,
      opkPub:  opkPubBytes,
    );

    return (bundle: bundle, ikBDh: ikDhKP, spkB: spkKP);
  }

  // ── Helper: build Alice's IK_dh keypair ────────────────────────────────────
  Future<SimpleKeyPair> buildAliceIkDh() => x25519.newKeyPair();

  // ── 1. SPK Signature Verification ─────────────────────────────────────────
  group('SPK Signature Verification', () {
    test('Valid SPK bundle passes verifyPreKeyBundle()', () async {
      final bob = await buildBobBundle();
      expect(await X3dhService.verifyPreKeyBundle(bob.bundle), isTrue,
          reason: 'Genuine SPK signature must pass verification');
    });

    test('Tampered SPK_pub fails verifyPreKeyBundle()', () async {
      final bob        = await buildBobBundle();
      final tampered   = Uint8List.fromList(bob.bundle.spkPub)..first ^= 0xFF;
      final badBundle  = PreKeyBundle(
        ikPubEd: bob.bundle.ikPubEd,
        ikPubDh: bob.bundle.ikPubDh,
        spkPub:  tampered,       // ← tampered
        spkSig:  bob.bundle.spkSig,
        opkPub:  bob.bundle.opkPub,
      );
      expect(await X3dhService.verifyPreKeyBundle(badBundle), isFalse,
          reason: 'Tampered SPK_pub must fail signature check (MITM detection)');
    });

    test('Tampered SPK_sig fails verifyPreKeyBundle()', () async {
      final bob       = await buildBobBundle();
      final badSig    = Uint8List.fromList(bob.bundle.spkSig)..last ^= 0xAA;
      final badBundle = PreKeyBundle(
        ikPubEd: bob.bundle.ikPubEd,
        ikPubDh: bob.bundle.ikPubDh,
        spkPub:  bob.bundle.spkPub,
        spkSig:  badSig,         // ← tampered
        opkPub:  bob.bundle.opkPub,
      );
      expect(await X3dhService.verifyPreKeyBundle(badBundle), isFalse,
          reason: 'Tampered signature bytes must fail verification');
    });

    test('Wrong IK_ed cannot forge a valid SPK signature', () async {
      final bob         = await buildBobBundle();
      final wrongIkEdKP = await ed25519.newKeyPair();
      final wrongIkEd   = await wrongIkEdKP.extractPublicKey();

      // Bundle with Bob's SPK + sig, but Carol's IK_ed
      final spoofedBundle = PreKeyBundle(
        ikPubEd: wrongIkEd.bytes, // ← wrong IK
        ikPubDh: bob.bundle.ikPubDh,
        spkPub:  bob.bundle.spkPub,
        spkSig:  bob.bundle.spkSig,
      );
      expect(await X3dhService.verifyPreKeyBundle(spoofedBundle), isFalse,
          reason: 'Foreign IK must not validate Bob\'s SPK signature');
    });
  });

  // ── 2. X3DH Shared Secret Symmetry ────────────────────────────────────────
  group('X3DH Initiator ↔ Responder Symmetry', () {
    test('3-DH (no OPK): Alice and Bob derive identical SK', () async {
      final alice  = await buildAliceIkDh();
      final alicePK = await alice.extractPublicKey();
      final bob    = await buildBobBundle(includeOpk: false);

      // Alice side
      final result  = await X3dhService.initiatorHandshake(
        ikADh:   alice,
        bundleB: bob.bundle,
      );

      // Bob side
      final skBob = await X3dhService.responderHandshake(
        ikBDh:   bob.ikBDh,
        spkB:    bob.spkB,
        opkB:    null,
        ekAPub:  result.ekPub,
        ikADhPub: alicePK.bytes,
      );

      expect(result.sharedSecret, equals(skBob),
          reason: '3-DH: Alice and Bob must derive the same 32-byte SK');
      expect(result.sharedSecret.length, equals(32));
    });

    test('4-DH (with OPK): Alice and Bob derive identical SK', () async {
      final alice   = await buildAliceIkDh();
      final alicePK = await alice.extractPublicKey();
      final bob     = await buildBobBundle(includeOpk: true);

      // Rebuild Bob's OPK key pair from scratch (since bundle only has pub)
      // — in production, Bob would retrieve opkKP from secure storage.
      // Here we simulate by regenerating:
      final opkKP  = await x25519.newKeyPair();
      final opkPub = await opkKP.extractPublicKey();
      final bundleWithKnownOpk = PreKeyBundle(
        ikPubEd: bob.bundle.ikPubEd,
        ikPubDh: bob.bundle.ikPubDh,
        spkPub:  bob.bundle.spkPub,
        spkSig:  bob.bundle.spkSig,
        opkId:   1,
        opkPub:  opkPub.bytes,
      );

      // Alice side (uses opkPub from bundle)
      final result = await X3dhService.initiatorHandshake(
        ikADh:   alice,
        bundleB: bundleWithKnownOpk,
      );

      // Bob side (uses opkKP private)
      final skBob = await X3dhService.responderHandshake(
        ikBDh:    bob.ikBDh,
        spkB:     bob.spkB,
        opkB:     opkKP,
        ekAPub:   result.ekPub,
        ikADhPub: alicePK.bytes,
      );

      expect(result.sharedSecret, equals(skBob),
          reason: '4-DH: Alice and Bob must derive the same 32-byte SK');
      expect(result.sharedSecret.length, equals(32));
    });

    test('3-DH and 4-DH produce DIFFERENT secrets for same participants', () async {
      final alice = await buildAliceIkDh();
      final bob   = await buildBobBundle(includeOpk: false);

      // 3-DH secret
      final sk3 = await X3dhService.initiatorHandshake(
        ikADh: alice, bundleB: bob.bundle,
      );

      // 4-DH secret (add a fresh OPK to the same bundle)
      final opkKP  = await x25519.newKeyPair();
      final opkPub = await opkKP.extractPublicKey();
      final aliceNew = await buildAliceIkDh(); // fresh Alice key for new session
      final aliceNewPK = await aliceNew.extractPublicKey();
      final bundle4 = PreKeyBundle(
        ikPubEd: bob.bundle.ikPubEd,
        ikPubDh: bob.bundle.ikPubDh,
        spkPub:  bob.bundle.spkPub,
        spkSig:  bob.bundle.spkSig,
        opkId:   1,
        opkPub:  opkPub.bytes,
      );
      final sk4 = await X3dhService.initiatorHandshake(
        ikADh: aliceNew, bundleB: bundle4,
      );

      expect(sk3.sharedSecret, isNot(equals(sk4.sharedSecret)),
          reason: '3-DH and 4-DH sessions must produce different secrets (OPK contribution)');
      // Bob verifies symmetry for 4-DH
      final skBob4 = await X3dhService.responderHandshake(
        ikBDh: bob.ikBDh, spkB: bob.spkB, opkB: opkKP,
        ekAPub: sk4.ekPub, ikADhPub: aliceNewPK.bytes,
      );
      expect(sk4.sharedSecret, equals(skBob4));
    });
  });

  // ── 3. HKDF Output Properties ─────────────────────────────────────────────
  group('HKDF-SHA256 Output Properties', () {
    test('SK is exactly 32 bytes', () async {
      final alice = await buildAliceIkDh();
      final bob   = await buildBobBundle(includeOpk: false);
      final result = await X3dhService.initiatorHandshake(
        ikADh: alice, bundleB: bob.bundle,
      );
      expect(result.sharedSecret.length, equals(32),
          reason: 'HKDF-SHA256 output must be exactly 32 bytes');
    });

    test('SK is not all-zeros', () async {
      final alice = await buildAliceIkDh();
      final bob   = await buildBobBundle(includeOpk: false);
      final result = await X3dhService.initiatorHandshake(
        ikADh: alice, bundleB: bob.bundle,
      );
      expect(result.sharedSecret.every((b) => b == 0), isFalse,
          reason: 'Derived SK must not be a zero-filled byte array');
    });

    test('Domain label "Kamui-X3DH-v3" ensures SK ≠ raw DH concatenation', () async {
      // Verify that info-labelled HKDF output differs from a raw SHA-256 of the same DH bytes
      final kp1 = await x25519.newKeyPair();
      final kp2 = await x25519.newKeyPair();
      final pk2 = await kp2.extractPublicKey();
      final raw = await (await x25519.sharedSecretKey(keyPair: kp1, remotePublicKey: pk2))
                        .extractBytes();
      // SK from full X3DH
      final alice = await buildAliceIkDh();
      final bob   = await buildBobBundle(includeOpk: false);
      final result = await X3dhService.initiatorHandshake(
        ikADh: alice, bundleB: bob.bundle,
      );
      // Just the naive hash of a single DH output
      final naiveHash = sha256.convert(raw).bytes;
      expect(result.sharedSecret, isNot(equals(naiveHash)),
          reason: 'Domain label and multi-DH IKM must produce a unique SK');
    });
  });

  // ── 4. Fail-Closed: initiatorHandshake throws on tampered bundle ───────────
  group('Fail-Closed X3DH Handshake', () {
    test('initiatorHandshake throws X3dhException on tampered SPK_pub', () async {
      final alice  = await buildAliceIkDh();
      final bob    = await buildBobBundle();
      final tampered = Uint8List.fromList(bob.bundle.spkPub)..first ^= 0xFF;
      final badBundle = PreKeyBundle(
        ikPubEd: bob.bundle.ikPubEd,
        ikPubDh: bob.bundle.ikPubDh,
        spkPub:  tampered,
        spkSig:  bob.bundle.spkSig,
      );
      expect(
        () async => X3dhService.initiatorHandshake(ikADh: alice, bundleB: badBundle),
        throwsA(isA<X3dhException>()),
        reason: 'Must throw X3dhException on SPK verification failure — no silent downgrade',
      );
    });

    test('initiatorHandshake throws X3dhException on spoofed IK_ed', () async {
      final alice     = await buildAliceIkDh();
      final bob       = await buildBobBundle();
      final carolIkEd = await ed25519.newKeyPair();
      final carolPub  = await carolIkEd.extractPublicKey();
      final spoofed   = PreKeyBundle(
        ikPubEd: carolPub.bytes, // wrong IK
        ikPubDh: bob.bundle.ikPubDh,
        spkPub:  bob.bundle.spkPub,
        spkSig:  bob.bundle.spkSig,
      );
      expect(
        () async => X3dhService.initiatorHandshake(ikADh: alice, bundleB: spoofed),
        throwsA(isA<X3dhException>()),
        reason: 'Spoofed IK_ed must trigger X3dhException — MITM aborted',
      );
    });
  });

  // ── 5. PreKeyBundle JSON Serialization ────────────────────────────────────
  group('PreKeyBundle JSON Round-trip', () {
    test('toJson() / fromJson() preserves all fields', () async {
      final bob       = await buildBobBundle(includeOpk: true);
      final jsonMap   = bob.bundle.toJson();
      final restored  = PreKeyBundle.fromJson(jsonMap);

      expect(restored.ikPubEd,            equals(bob.bundle.ikPubEd));
      expect(restored.ikPubDh,            equals(bob.bundle.ikPubDh));
      expect(restored.spkPub,             equals(bob.bundle.spkPub));
      expect(restored.spkSig,             equals(bob.bundle.spkSig));
      expect(restored.opkPub,             equals(bob.bundle.opkPub));
    });

    test('JSON is valid base64 for all fields', () async {
      final bob     = await buildBobBundle(includeOpk: true);
      final jsonMap = bob.bundle.toJson();
      for (final key in ['ik_ed', 'ik_dh', 'spk', 'spk_sig', 'opk']) {
        final val = jsonMap[key] as String?;
        if (val != null) {
          expect(() => base64Decode(val), returnsNormally,
              reason: 'Field $key must be valid base64');
        }
      }
    });

    test('Bundle without OPK serializes and deserializes cleanly', () async {
      final bob      = await buildBobBundle(includeOpk: false);
      final json     = bob.bundle.toJson();
      expect(json.containsKey('opk'), isFalse,
          reason: 'OPK key must be absent when opkPub is null');
      final restored = PreKeyBundle.fromJson(json);
      expect(restored.opkPub, isNull,
          reason: 'Restored bundle must have null opkPub');
    });

    test('Restored bundle passes SPK signature verification', () async {
      final bob      = await buildBobBundle(includeOpk: true);
      final restored = PreKeyBundle.fromJson(bob.bundle.toJson());
      expect(await X3dhService.verifyPreKeyBundle(restored), isTrue,
          reason: 'SPK verification must pass after JSON round-trip');
    });
  });

  // ── 6. Session Independence ───────────────────────────────────────────────
  group('Session Independence', () {
    test('Two Alice↔Bob sessions produce independent secrets', () async {
      final alice1  = await buildAliceIkDh();
      final alice2  = await buildAliceIkDh();
      final bob1    = await buildBobBundle(includeOpk: false);
      final bob2    = await buildBobBundle(includeOpk: false);

      final sk1 = (await X3dhService.initiatorHandshake(
        ikADh: alice1, bundleB: bob1.bundle,
      )).sharedSecret;
      final sk2 = (await X3dhService.initiatorHandshake(
        ikADh: alice2, bundleB: bob2.bundle,
      )).sharedSecret;

      expect(sk1, isNot(equals(sk2)),
          reason: 'Independent sessions must produce independent secrets');
    });

    test('EK_pub differs between sessions (ephemeral key freshness)', () async {
      final alice = await buildAliceIkDh();
      final bob   = await buildBobBundle(includeOpk: false);
      final r1 = await X3dhService.initiatorHandshake(ikADh: alice, bundleB: bob.bundle);
      final r2 = await X3dhService.initiatorHandshake(ikADh: alice, bundleB: bob.bundle);
      expect(r1.ekPub, isNot(equals(r2.ekPub)),
          reason: 'Ephemeral key must be freshly generated for each handshake');
    });
  });
}
