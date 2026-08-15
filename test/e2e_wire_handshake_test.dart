import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/identity_key_service.dart';
import 'package:kamui/services/session_manager.dart';
import 'package:kamui/services/x3dh_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('E2E Wire Handshake Integration (Alice ↔ Bob Live Wire Dispatch)', () {
    late IdentityKeyService aliceIdentity;
    late IdentityKeyService bobIdentity;
    late SessionManager aliceSessionManager;
    late SessionManager bobSessionManager;

    const convId = 'conv_e2e_alice_bob_1';

    setUp(() async {
      FlutterSecureStorage.setMockInitialValues({});

      // Isolated instances for Alice and Bob
      aliceIdentity = IdentityKeyService.isolated();
      bobIdentity   = IdentityKeyService.isolated();

      await aliceIdentity.init();
      await bobIdentity.init();

      aliceSessionManager = SessionManager.isolated(identityService: aliceIdentity);
      bobSessionManager   = SessionManager.isolated(identityService: bobIdentity);
    });

    test('Full Automatic Handshake & Bidirectional v4 Message Exchange over the Wire', () async {
      // 1. Bob exports his PreKeyBundle (published via QR or Handshake Payload)
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      expect(bobBundle, isNotNull);
      final bobBundleJson = jsonEncode(bobBundle!.toJson());

      // 2. Alice sends her FIRST message to Bob using Bob's PreKeyBundle
      const aliceFirstPlaintext = 'Hello Bob! This is Alice initiating secure Kamui v4.';
      final firstWirePayload = await aliceSessionManager.encryptV4(
        convId,
        aliceFirstPlaintext,
        peerPreKeyBundleJson: bobBundleJson,
      );

      // Verify the first message is wrapped in a valid HandshakeInitEnvelope
      expect(HandshakeInitEnvelope.isHandshakeEnvelope(firstWirePayload), isTrue);
      final envelopeJson = jsonDecode(firstWirePayload) as Map<String, dynamic>;
      expect(envelopeJson['type'], equals('kamui_v4_handshake_init'));
      expect(envelopeJson['first_message'].toString().startsWith('kamui_v4:'), isTrue);

      // 3. Bob receives the raw wire payload directly via his SessionManager.decryptV4
      // NOTE: responderHandshake and DoubleRatchetSession.initBob are NEVER called manually here!
      final bobDecryptedFirstMsg = await bobSessionManager.decryptV4(
        convId,
        firstWirePayload,
      );

      // Verify Bob automatically established the session and decrypted the plaintext
      expect(bobDecryptedFirstMsg, equals(aliceFirstPlaintext));

      // 4. Bob sends a reply back to Alice
      const bobReplyPlaintext = 'Greetings Alice! Bob received your v4 handshake perfectly.';
      final bobReplyWirePayload = await bobSessionManager.encryptV4(
        convId,
        bobReplyPlaintext,
      );

      // Subsequent messages are standard Double Ratchet wire frames
      expect(bobReplyWirePayload.startsWith('kamui_v4:'), isTrue);

      // 5. Alice decrypts Bob's reply
      final aliceDecryptedReply = await aliceSessionManager.decryptV4(
        convId,
        bobReplyWirePayload,
      );
      expect(aliceDecryptedReply, equals(bobReplyPlaintext));

      // 6. Alice sends a second message (now in active ratchet mode)
      const aliceSecondPlaintext = 'Ratchet step active: message 2 from Alice.';
      final aliceSecondWirePayload = await aliceSessionManager.encryptV4(
        convId,
        aliceSecondPlaintext,
      );
      expect(aliceSecondWirePayload.startsWith('kamui_v4:'), isTrue);

      final bobDecryptedSecondMsg = await bobSessionManager.decryptV4(
        convId,
        aliceSecondWirePayload,
      );
      expect(bobDecryptedSecondMsg, equals(aliceSecondPlaintext));

      // 7. REPLAY ATTACK PREVENTION:
      // An attacker captures and replays the original firstWirePayload to Bob.
      // Because Bob already consumed OPK #1, Bob MUST reject the replayed handshake envelope.
      expect(
        () async => await bobSessionManager.decryptV4(convId, firstWirePayload),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Replaying an already-consumed HandshakeInitEnvelope must fail closed',
      );
    });

    test('Tampered HandshakeInitEnvelope is rejected by Bob (Fail-Closed)', () async {
      final bobBundle = await bobIdentity.generatePreKeyBundleAsync();
      final bobBundleJson = jsonEncode(bobBundle!.toJson());

      final genuinePayload = await aliceSessionManager.encryptV4(
        convId,
        'Sensitive data',
        peerPreKeyBundleJson: bobBundleJson,
      );

      // Tamper with Alice's ephemeral key in envelope
      final map = jsonDecode(genuinePayload) as Map<String, dynamic>;
      map['ek'] = base64Encode(List.filled(32, 0xAA)); // Corrupted EK
      final tamperedPayload = jsonEncode(map);

      expect(
        () async => await bobSessionManager.decryptV4(convId, tamperedPayload),
        throwsA(isA<SessionUnavailableException>()),
        reason: 'Corrupted HandshakeInitEnvelope must be rejected',
      );
    });
  });
}
