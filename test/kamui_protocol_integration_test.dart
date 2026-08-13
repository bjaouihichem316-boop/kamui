// ignore_for_file: avoid_print

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/double_ratchet.dart';
import 'package:kamui/services/x3dh_service.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Kamui Protocol Integration & Threat Modeling Tests
// ══════════════════════════════════════════════════════════════════════════════

void main() {
  const convId = 'integration-conv';
  const peerB64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  final ed25519 = Ed25519();
  final x25519  = X25519();

  /// Helper to simulate Bob publishing his PreKeyBundle
  Future<(SimpleKeyPair ikEd, SimpleKeyPair ikDh, SimpleKeyPair spk, SimpleKeyPair opk, PreKeyBundle bundle)> buildBobNode() async {
    final ikEd = await ed25519.newKeyPair();
    final ikDh = await x25519.newKeyPair();
    final spk  = await x25519.newKeyPair();
    final opk  = await x25519.newKeyPair();

    final ikEdPub = await ikEd.extractPublicKey();
    final ikDhPub = await ikDh.extractPublicKey();
    final spkPub  = await spk.extractPublicKey();
    final opkPub  = await opk.extractPublicKey();

    // Bob signs his SPK with his Ed25519 Identity Key
    final spkSig = await ed25519.sign(spkPub.bytes, keyPair: ikEd);

    final bundle = PreKeyBundle(
      ikPubEd: ikEdPub.bytes,
      ikPubDh: ikDhPub.bytes,
      spkPub:  spkPub.bytes,
      spkSig:  spkSig.bytes,
      opkPub:  opkPub.bytes,
    );

    return (ikEd, ikDh, spk, opk, bundle);
  }

  group('Protocol Integration & Threat Modeling', () {
    test('1. Full E2EE Flow (X3DH -> Double Ratchet -> Decryption)', () async {
      // 1. Bob generates his identity and prekeys
      final bobNode = await buildBobNode();
      final bobBundle = bobNode.$5;

      // 2. Alice generates her DH identity key
      final aliceIkDh = await x25519.newKeyPair();
      final aliceIkDhPub = await aliceIkDh.extractPublicKey();

      // 3. Alice performs X3DH Initiator Handshake using Bob's bundle
      final aliceX3dh = await X3dhService.initiatorHandshake(
        ikADh: aliceIkDh,
        bundleB: bobBundle,
      );

      // 4. Alice initializes her Double Ratchet Session
      final aliceSession = await DoubleRatchetSession.initAlice(
        conversationId: convId,
        peerIdentityPublicKeyB64: peerB64,
        sk: aliceX3dh.sharedSecret,
        bobSpkPub: bobBundle.spkPub,
      );

      // 5. Alice sends her first message
      final wire1 = await aliceSession.encrypt('Hello Bob!');

      // 6. Bob receives the first message. Before decrypting, Bob must do X3DH Responder Handshake.
      // In reality, Alice's EK and IK would be sent alongside the first message or out-of-band.
      // For this integration test, we extract them directly.
      final bobX3dhSk = await X3dhService.responderHandshake(
        ikBDh: bobNode.$2,
        spkB:  bobNode.$3,
        opkB:  bobNode.$4,
        ekAPub: aliceX3dh.ekPub,
        ikADhPub: aliceIkDhPub.bytes,
      );

      expect(bobX3dhSk, equals(aliceX3dh.sharedSecret), reason: 'X3DH Shared Secrets must match');

      // 7. Bob initializes his Double Ratchet Session
      final bobSession = await DoubleRatchetSession.initBob(
        conversationId: convId,
        peerIdentityPublicKeyB64: peerB64,
        sk: bobX3dhSk,
        spkBDh: bobNode.$3, // Bob uses SPK as initial ratchet keypair
      );

      // 8. Bob decrypts Alice's first message (triggers Bob's DH ratchet step)
      final plain1 = await bobSession.decrypt(wire1);
      expect(plain1, equals('Hello Bob!'));

      // 9. Bob replies to Alice
      final wire2 = await bobSession.encrypt('Hello Alice, secure channel established.');
      final plain2 = await aliceSession.decrypt(wire2);
      expect(plain2, equals('Hello Alice, secure channel established.'));
    });

    test('2. Replay Attack Prevention', () async {
      final bobNode = await buildBobNode();
      final aliceIkDh = await x25519.newKeyPair();
      final aliceX3dh = await X3dhService.initiatorHandshake(ikADh: aliceIkDh, bundleB: bobNode.$5);
      final aliceSession = await DoubleRatchetSession.initAlice(
        conversationId: convId, peerIdentityPublicKeyB64: peerB64, sk: aliceX3dh.sharedSecret, bobSpkPub: bobNode.$5.spkPub,
      );
      
      final aliceIkDhPub = await aliceIkDh.extractPublicKey();
      final bobX3dhSk = await X3dhService.responderHandshake(
        ikBDh: bobNode.$2, spkB: bobNode.$3, opkB: bobNode.$4, ekAPub: aliceX3dh.ekPub, ikADhPub: aliceIkDhPub.bytes,
      );
      final bobSession = await DoubleRatchetSession.initBob(
        conversationId: convId, peerIdentityPublicKeyB64: peerB64, sk: bobX3dhSk, spkBDh: bobNode.$3,
      );

      final wire = await aliceSession.encrypt('Important Transfer');
      await bobSession.decrypt(wire); // Success

      // Attack: Replay the exact same ciphertext
      expect(
        () async => await bobSession.decrypt(wire),
        throwsA(isA<RatchetException>()),
        reason: 'Replayed messages must be rejected strictly (Fail-Closed)',
      );
    });

    test('3. Out-of-order Sequence Recovery', () async {
      final bobNode = await buildBobNode();
      final aliceIkDh = await x25519.newKeyPair();
      final aliceX3dh = await X3dhService.initiatorHandshake(ikADh: aliceIkDh, bundleB: bobNode.$5);
      final aliceSession = await DoubleRatchetSession.initAlice(
        conversationId: convId, peerIdentityPublicKeyB64: peerB64, sk: aliceX3dh.sharedSecret, bobSpkPub: bobNode.$5.spkPub,
      );
      
      final aliceIkDhPub = await aliceIkDh.extractPublicKey();
      final bobX3dhSk = await X3dhService.responderHandshake(
        ikBDh: bobNode.$2, spkB: bobNode.$3, opkB: bobNode.$4, ekAPub: aliceX3dh.ekPub, ikADhPub: aliceIkDhPub.bytes,
      );
      final bobSession = await DoubleRatchetSession.initBob(
        conversationId: convId, peerIdentityPublicKeyB64: peerB64, sk: bobX3dhSk, spkBDh: bobNode.$3,
      );

      final wire0 = await aliceSession.encrypt('Msg 0');
      final wire1 = await aliceSession.encrypt('Msg 1');
      final wire2 = await aliceSession.encrypt('Msg 2');

      // Bob receives 2 first, then 0, then 1 (Scrambled)
      expect(await bobSession.decrypt(wire2), equals('Msg 2'));
      expect(await bobSession.decrypt(wire0), equals('Msg 0'));
      expect(await bobSession.decrypt(wire1), equals('Msg 1'));
    });

    test('4. Identity Swap Detection (MITM on SPK_pub)', () async {
      final bobNode = await buildBobNode();
      final bundle = bobNode.$5;

      // Eve swaps the SPK_pub with her own
      final eveSpk = await x25519.newKeyPair();
      final eveSpkPub = await eveSpk.extractPublicKey();
      
      final tamperedBundle = PreKeyBundle(
        ikPubEd: bundle.ikPubEd,
        ikPubDh: bundle.ikPubDh,
        spkPub: eveSpkPub.bytes, // Tampered!
        spkSig: bundle.spkSig,   // Original signature (invalid for new SPK)
        opkPub: bundle.opkPub,
      );

      final aliceIkDh = await x25519.newKeyPair();

      // X3DH should instantly fail (Fail-Closed)
      expect(
        () async => await X3dhService.initiatorHandshake(ikADh: aliceIkDh, bundleB: tamperedBundle),
        throwsA(isA<X3dhException>()),
        reason: 'Tampered SPK must fail signature verification and abort session (Identity Swap)',
      );
    });

    test('5. Fail-Closed Ciphertext Tampering', () async {
      final bobNode = await buildBobNode();
      final aliceIkDh = await x25519.newKeyPair();
      final aliceX3dh = await X3dhService.initiatorHandshake(ikADh: aliceIkDh, bundleB: bobNode.$5);
      final aliceSession = await DoubleRatchetSession.initAlice(
        conversationId: convId, peerIdentityPublicKeyB64: peerB64, sk: aliceX3dh.sharedSecret, bobSpkPub: bobNode.$5.spkPub,
      );
      
      final aliceIkDhPub = await aliceIkDh.extractPublicKey();
      final bobX3dhSk = await X3dhService.responderHandshake(
        ikBDh: bobNode.$2, spkB: bobNode.$3, opkB: bobNode.$4, ekAPub: aliceX3dh.ekPub, ikADhPub: aliceIkDhPub.bytes,
      );
      final bobSession = await DoubleRatchetSession.initBob(
        conversationId: convId, peerIdentityPublicKeyB64: peerB64, sk: bobX3dhSk, spkBDh: bobNode.$3,
      );

      final wire = await aliceSession.encrypt('Top Secret');
      final parts = wire.split(':');
      
      // Tamper with the MAC (last segment)
      final tamperedWire = '${parts[0]}:${parts[1]}:${parts[2]}:${parts[3].substring(0, parts[3].length - 4)}AAAA';

      expect(
        () async => await bobSession.decrypt(tamperedWire),
        throwsA(isA<RatchetException>()),
        reason: 'Ciphertext tampering must throw RatchetException (Fail-Closed)',
      );
    });
  });
}
