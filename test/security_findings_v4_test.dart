import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/identity_key_service.dart';
import 'package:kamui/services/session_manager.dart';
import 'package:kamui/services/x3dh_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final ed25519 = Ed25519();
  final x25519  = X25519();

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
  });

  // ══════════════════════════════════════════════════════════════════════════════
  // FINDING 1: OPK CONSUMPTION TIMING & TRANSACTIONAL INTEGRITY
  // ══════════════════════════════════════════════════════════════════════════════
  group('Finding 1 — Transactional OPK Consumption & First-Message Authentication', () {
    late IdentityKeyService aliceIdentity;
    late IdentityKeyService bobIdentity;
    late SessionManager aliceSessionManager;
    late SessionManager bobSessionManager;

    const convId = 'conv_finding_1_test';

    setUp(() async {
      aliceIdentity = IdentityKeyService.isolated();
      bobIdentity   = IdentityKeyService.isolated();

      await aliceIdentity.init();
      await bobIdentity.init();

      aliceSessionManager = SessionManager.isolated(identityService: aliceIdentity);
      bobSessionManager   = SessionManager.isolated(identityService: bobIdentity);
    });

    test('A. Valid handshake consumes OPK upon successful first-message decryption', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      expect(bobBundle!.opkId, equals(1));
      expect(bobIdentity.getOpk(1), isNotNull);

      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Valid first message',
        peerPreKeyBundleJson: jsonEncode(bobBundle.toJson()),
      );

      final decrypted = await bobSessionManager.decryptV4(convId, wirePayload);
      expect(decrypted, equals('Valid first message'));

      // The OPK actually selected by the initiator (pool-aware) must now be
      // consumed — replay/reuse of that exact OPK fails closed.
      final envelope = HandshakeInitEnvelope.fromJson(jsonDecode(wirePayload));
      final usedOpkId = envelope.opkIdUsed;
      expect(usedOpkId, isNotNull);
      expect(bobBundle.opks.containsKey(usedOpkId), isTrue,
          reason: 'used OPK must come from the published pool');
      expect(
        () => bobIdentity.getOpk(usedOpkId!),
        throwsA(isA<X3dhException>()),
        reason: 'OPK must be consumed after successful authentication',
      );
    });

    test('B. Corrupted first_message does NOT consume OPK (OPK remains available for genuine sender)', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      expect(bobBundle!.opkId, equals(1));
      expect(bobIdentity.getOpk(1), isNotNull);

      final validWire = await aliceSessionManager.encryptV4(
        convId,
        'Genuine payload',
        peerPreKeyBundleJson: jsonEncode(bobBundle.toJson()),
      );

      // Malicious attacker corrupts first_message ciphertext (bad AEAD MAC)
      final envelopeMap = jsonDecode(validWire) as Map<String, dynamic>;
      final parts = (envelopeMap['first_message'] as String).split(':');
      // Tamper ciphertext
      final corruptedFirstMsg = '${parts[0]}:${parts[1]}:${parts[2]}:${parts[3].substring(0, parts[3].length - 4)}FFFF';
      envelopeMap['first_message'] = corruptedFirstMsg;
      final corruptedPayload = jsonEncode(envelopeMap);

      // Bob attempts to decrypt corrupted envelope
      expect(
        () async => await bobSessionManager.decryptV4(convId, corruptedPayload),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Corrupted first_message must fail AEAD verification',
      );

      // OPK 1 must NOT have been consumed
      expect(bobIdentity.getOpk(1), isNotNull,
          reason: 'Failed AEAD decryption must preserve OPK in store');
    });

    test('C. Corrupted first_message commits NO session to Bob\'s active sessions', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final validWire = await aliceSessionManager.encryptV4(
        convId,
        'Valid text',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      final envelopeMap = jsonDecode(validWire) as Map<String, dynamic>;
      final parts = (envelopeMap['first_message'] as String).split(':');
      envelopeMap['first_message'] = '${parts[0]}:${parts[1]}:${parts[2]}:INVALIDCIPHERTEXT';
      final corruptedPayload = jsonEncode(envelopeMap);

      try {
        await bobSessionManager.decryptV4(convId, corruptedPayload);
      } catch (_) {}

      // Bob's session must not exist — subsequent non-handshake messages should fail
      expect(
        () async => await bobSessionManager.encryptV4(convId, 'Reply to unestablished session'),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'No session must be committed if first message failed authentication',
      );
    });

    test('D. Replay of the same handshake after successful consumption is rejected', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Original Message',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      // First delivery succeeds
      final dec1 = await bobSessionManager.decryptV4(convId, wirePayload);
      expect(dec1, equals('Original Message'));

      // Replay attempt
      expect(
        () async => await bobSessionManager.decryptV4(convId, wirePayload),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Replayed handshake envelope must be rejected fail-closed',
      );
    });

    test('E. Multiple malicious handshakes cannot exhaust Bob\'s OPK pool without successful authentication', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();

      // Attacker sends 10 malicious handshakes with forged ciphertexts
      for (int i = 0; i < 10; i++) {
        final rogueAliceId = IdentityKeyService.isolated();
        await rogueAliceId.init();
        final rogueSessionMgr = SessionManager.isolated(identityService: rogueAliceId);

        final rogueWire = await rogueSessionMgr.encryptV4(
          'rogue_conv_$i',
          'Rogue msg',
          peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
        );

        final envelopeMap = jsonDecode(rogueWire) as Map<String, dynamic>;
        final parts = (envelopeMap['first_message'] as String).split(':');
        envelopeMap['first_message'] = '${parts[0]}:${parts[1]}:${parts[2]}:BADMACBADMAC';
        final corruptedRogueWire = jsonEncode(envelopeMap);

        expect(
          () async => await bobSessionManager.decryptV4('rogue_conv_$i', corruptedRogueWire),
          throwsA(isA<SessionUnavailableException>()),
        );
      }

      // Bob's entire OPK pool is still available and untouched!
      for (final poolId in bobBundle!.opks.keys) {
        expect(bobIdentity.getOpk(poolId), isNotNull,
            reason: 'failed attacks must not consume pool OPK $poolId');
      }

      // Genuine Alice can now still successfully establish session using Bob's OPK pool
      final genuineWire = await aliceSessionManager.encryptV4(
        convId,
        'Genuine Alice message after 10 failed attacks',
        peerPreKeyBundleJson: jsonEncode(bobBundle.toJson()),
      );

      final genuineDecrypted = await bobSessionManager.decryptV4(convId, genuineWire);
      expect(genuineDecrypted, equals('Genuine Alice message after 10 failed attacks'));

      // Only now is the genuinely-used OPK consumed
      final genuineEnvelope = HandshakeInitEnvelope.fromJson(jsonDecode(genuineWire));
      expect(
        () => bobIdentity.getOpk(genuineEnvelope.opkIdUsed!),
        throwsA(isA<X3dhException>()),
      );
    });
  });

  // ══════════════════════════════════════════════════════════════════════════════
  // FINDING 2: IK_ED / IK_DH CRYPTOGRAPHIC IDENTITY BINDING
  // ══════════════════════════════════════════════════════════════════════════════
  group('Finding 2 — IK_ed / IK_dh Cryptographic Identity Binding Verification', () {
    late IdentityKeyService aliceIdentity;
    late IdentityKeyService bobIdentity;
    late SessionManager aliceSessionManager;
    late SessionManager bobSessionManager;

    const convId = 'conv_finding_2_test';

    setUp(() async {
      aliceIdentity = IdentityKeyService.isolated();
      bobIdentity   = IdentityKeyService.isolated();

      await aliceIdentity.init();
      await bobIdentity.init();

      aliceSessionManager = SessionManager.isolated(identityService: aliceIdentity);
      bobSessionManager   = SessionManager.isolated(identityService: bobIdentity);
    });

    test('A. Valid identity binding is accepted and verified', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Hello with valid identity binding',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      final envelope = HandshakeInitEnvelope.fromJson(jsonDecode(wirePayload));
      expect(envelope.ikSig.length, equals(64));

      final isValid = await X3dhService.verifyIdentityBinding(
        ikEd:  envelope.ikEd,
        ikDh:  envelope.ikDh,
        ikSig: envelope.ikSig,
      );
      expect(isValid, isTrue);

      final decrypted = await bobSessionManager.decryptV4(convId, wirePayload);
      expect(decrypted, equals('Hello with valid identity binding'));
    });

    test('B. Modified ik_dh in envelope is rejected (Fail-Closed)', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Secret',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      final envelopeMap = jsonDecode(wirePayload) as Map<String, dynamic>;
      final alteredDh = base64Decode(envelopeMap['ik_dh'] as String);
      alteredDh[0] ^= 0xFF; // Modify IK_dh
      envelopeMap['ik_dh'] = base64Encode(alteredDh);
      final tamperedWire = jsonEncode(envelopeMap);

      expect(
        () async => await bobSessionManager.decryptV4(convId, tamperedWire),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Tampered ik_dh must fail identity binding verification',
      );
    });

    test('C. Modified ik_ed in envelope is rejected (Fail-Closed)', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Secret',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      final envelopeMap = jsonDecode(wirePayload) as Map<String, dynamic>;
      final alteredEd = base64Decode(envelopeMap['ik_ed'] as String);
      alteredEd[0] ^= 0xAA; // Modify IK_ed
      envelopeMap['ik_ed'] = base64Encode(alteredEd);
      final tamperedWire = jsonEncode(envelopeMap);

      expect(
        () async => await bobSessionManager.decryptV4(convId, tamperedWire),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Tampered ik_ed must fail identity binding verification',
      );
    });

    test('D. Modified signature in envelope is rejected (Fail-Closed)', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Secret',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      final envelopeMap = jsonDecode(wirePayload) as Map<String, dynamic>;
      final alteredSig = base64Decode(envelopeMap['ik_sig'] as String);
      alteredSig[alteredSig.length - 1] ^= 0x55; // Modify signature
      envelopeMap['ik_sig'] = base64Encode(alteredSig);
      final tamperedWire = jsonEncode(envelopeMap);

      expect(
        () async => await bobSessionManager.decryptV4(convId, tamperedWire),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Tampered ik_sig must fail signature verification',
      );
    });

    test('E. Signature generated from another identity key is rejected', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Secret',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      // Mallory signs Alice's transcript with Mallory's distinct key
      final malloryKey = await ed25519.newKeyPair();

      final envelopeMap = jsonDecode(wirePayload) as Map<String, dynamic>;
      final ikEdBytes = base64Decode(envelopeMap['ik_ed'] as String);
      final ikDhBytes = base64Decode(envelopeMap['ik_dh'] as String);
      final transcript = X3dhService.computeIdentityBindingTranscript(ikEdBytes, ikDhBytes);
      final mallorySig = await ed25519.sign(transcript, keyPair: malloryKey);

      envelopeMap['ik_sig'] = base64Encode(mallorySig.bytes);
      final tamperedWire = jsonEncode(envelopeMap);

      expect(
        () async => await bobSessionManager.decryptV4(convId, tamperedWire),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Signature from another identity must not validate against Alice\'s IK_ed',
      );
    });

    test('F. Malformed signature bytes (wrong length) is rejected', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final wirePayload = await aliceSessionManager.encryptV4(
        convId,
        'Secret',
        peerPreKeyBundleJson: jsonEncode(bobBundle!.toJson()),
      );

      final envelopeMap = jsonDecode(wirePayload) as Map<String, dynamic>;
      envelopeMap['ik_sig'] = base64Encode(Uint8List(32)); // 32 bytes instead of 64 bytes
      final tamperedWire = jsonEncode(envelopeMap);

      expect(
        () async => await bobSessionManager.decryptV4(convId, tamperedWire),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Malformed signature length must be rejected',
      );
    });
  });

  // ══════════════════════════════════════════════════════════════════════════════
  // FINDING 3: PREKEYBUNDLE OPK CONSISTENCY (FOUR EXPLICIT STATES)
  // ══════════════════════════════════════════════════════════════════════════════
  group('Finding 3 — PreKeyBundle OPK Consistency Validation (4 Explicit States)', () {
    late SimpleKeyPair aliceIkDh;
    late SimpleKeyPair bobIkEd;
    late SimpleKeyPair bobIkDh;
    late SimpleKeyPair bobSpk;
    late List<int> spkSig;

    setUp(() async {
      aliceIkDh = await x25519.newKeyPair();
      bobIkEd   = await ed25519.newKeyPair();
      bobIkDh   = await x25519.newKeyPair();
      bobSpk    = await x25519.newKeyPair();

      final bobSpkPub = await bobSpk.extractPublicKey();
      final sig = await ed25519.sign(bobSpkPub.bytes, keyPair: bobIkEd);
      spkSig = sig.bytes;
    });

    test('State 1: No OPK (opkId == null && opkPub == null) is VALID 3-DH', () async {
      final bobIkEdPub = await bobIkEd.extractPublicKey();
      final bobIkDhPub = await bobIkDh.extractPublicKey();
      final bobSpkPub  = await bobSpk.extractPublicKey();

      final bundle = PreKeyBundle(
        ikPubEd: bobIkEdPub.bytes,
        ikPubDh: bobIkDhPub.bytes,
        spkPub:  bobSpkPub.bytes,
        spkSig:  spkSig,
        opkId:   null,
        opkPub:  null,
      );

      final result = await X3dhService.initiatorHandshake(
        ikADh:   aliceIkDh,
        bundleB: bundle,
      );

      expect(result.sharedSecret.length, equals(32));
      expect(result.opkId, isNull);
    });

    test('State 2: Valid OPK (opkId != null && opkPub != null) is VALID 4-DH', () async {
      final bobIkEdPub = await bobIkEd.extractPublicKey();
      final bobIkDhPub = await bobIkDh.extractPublicKey();
      final bobSpkPub  = await bobSpk.extractPublicKey();
      final bobOpk     = await x25519.newKeyPair();
      final bobOpkPub  = await bobOpk.extractPublicKey();

      final bundle = PreKeyBundle(
        ikPubEd: bobIkEdPub.bytes,
        ikPubDh: bobIkDhPub.bytes,
        spkPub:  bobSpkPub.bytes,
        spkSig:  spkSig,
        opkId:   7,
        opkPub:  bobOpkPub.bytes,
      );

      final result = await X3dhService.initiatorHandshake(
        ikADh:   aliceIkDh,
        bundleB: bundle,
      );

      expect(result.sharedSecret.length, equals(32));
      expect(result.opkId, equals(7));
    });

    test('State 3: Malformed (opkId != null && opkPub == null) is REJECTED', () async {
      final bobIkEdPub = await bobIkEd.extractPublicKey();
      final bobIkDhPub = await bobIkDh.extractPublicKey();
      final bobSpkPub  = await bobSpk.extractPublicKey();

      final bundle = PreKeyBundle(
        ikPubEd: bobIkEdPub.bytes,
        ikPubDh: bobIkDhPub.bytes,
        spkPub:  bobSpkPub.bytes,
        spkSig:  spkSig,
        opkId:   4,
        opkPub:  null, // Missing key
      );

      expect(
        () async => await X3dhService.initiatorHandshake(ikADh: aliceIkDh, bundleB: bundle),
        throwsA(predicate((e) =>
            e is X3dhException &&
            e.reason.contains('opkId present without opkPub'))),
      );
    });

    test('State 4: Malformed (opkId == null && opkPub != null) is REJECTED (No fallback to 1)', () async {
      final bobIkEdPub = await bobIkEd.extractPublicKey();
      final bobIkDhPub = await bobIkDh.extractPublicKey();
      final bobSpkPub  = await bobSpk.extractPublicKey();
      final bobOpk     = await x25519.newKeyPair();
      final bobOpkPub  = await bobOpk.extractPublicKey();

      final bundle = PreKeyBundle(
        ikPubEd: bobIkEdPub.bytes,
        ikPubDh: bobIkDhPub.bytes,
        spkPub:  bobSpkPub.bytes,
        spkSig:  spkSig,
        opkId:   null, // Missing ID
        opkPub:  bobOpkPub.bytes,
      );

      expect(
        () async => await X3dhService.initiatorHandshake(ikADh: aliceIkDh, bundleB: bundle),
        throwsA(predicate((e) =>
            e is X3dhException &&
            e.reason.contains('opkPub present without explicit opkId'))),
      );
    });
  });
}
