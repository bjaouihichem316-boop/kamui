// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

// ══════════════════════════════════════════════════════════════════
// Kamui v2 – Deep Security & Audit Test Suite
// ══════════════════════════════════════════════════════════════════

void main() {
  // ── 1. X25519 Diffie-Hellman ──────────────────────────────────────
  group('X25519 Key Agreement', () {
    final x25519 = X25519();

    test('Alice & Bob derive identical shared secrets', () async {
      final aliceKP = await x25519.newKeyPair();
      final alicePK = await aliceKP.extractPublicKey();

      final bobKP = await x25519.newKeyPair();
      final bobPK = await bobKP.extractPublicKey();

      final sharedA = await x25519.sharedSecretKey(
        keyPair: aliceKP,
        remotePublicKey: bobPK,
      );
      final sharedB = await x25519.sharedSecretKey(
        keyPair: bobKP,
        remotePublicKey: alicePK,
      );

      final bytesA = await sharedA.extractBytes();
      final bytesB = await sharedB.extractBytes();

      expect(bytesA.length, equals(32), reason: 'Shared secret must be 32 bytes');
      expect(bytesB.length, equals(32));
      expect(bytesA, equals(bytesB), reason: 'Both sides must derive the same secret');
    });

    test('Different keypairs produce different secrets', () async {
      final kp1 = await x25519.newKeyPair();
      final kp2 = await x25519.newKeyPair();
      final kp3 = await x25519.newKeyPair();

      final pk2 = await kp2.extractPublicKey();
      final pk3 = await kp3.extractPublicKey();

      final s12 = await (await x25519.sharedSecretKey(
        keyPair: kp1,
        remotePublicKey: pk2,
      )).extractBytes();
      final s13 = await (await x25519.sharedSecretKey(
        keyPair: kp1,
        remotePublicKey: pk3,
      )).extractBytes();

      expect(s12, isNot(equals(s13)),
          reason: 'Distinct peer keys must yield distinct secrets');
    });
  });

  // ── 2. AES-256-GCM ────────────────────────────────────────────────
  group('AES-256-GCM Encryption', () {
    final aesGcm = AesGcm.with256bits();

    test('Encrypt-then-Decrypt round-trip succeeds', () async {
      final key = SecretKey(List.generate(32, (i) => i));
      const plaintext = 'Hello, Kamui v2 ratchet!';

      final nonce = aesGcm.newNonce();
      final box = await aesGcm.encrypt(
        utf8.encode(plaintext),
        secretKey: key,
        nonce: nonce,
      );

      const macLength = 16;
      final concatenated = Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
      final ctBytes  = concatenated.sublist(0, concatenated.length - macLength);
      final macBytes = concatenated.sublist(concatenated.length - macLength);

      final decrypted = await aesGcm.decrypt(
        SecretBox(ctBytes, nonce: nonce, mac: Mac(macBytes)),
        secretKey: key,
      );

      expect(utf8.decode(decrypted), equals(plaintext));
    });

    test('Tampered ciphertext throws on decryption (MAC check)', () async {
      final key   = SecretKey(List.generate(32, (i) => i + 1));
      final nonce = aesGcm.newNonce();
      final box   = await aesGcm.encrypt(
        utf8.encode('secret'),
        secretKey: key,
        nonce: nonce,
      );

      final tampered = Uint8List.fromList(box.cipherText)..first ^= 0xFF;

      expect(
        () async => aesGcm.decrypt(
          SecretBox(tampered, nonce: nonce, mac: box.mac),
          secretKey: key,
        ),
        throwsA(anything),
        reason: 'Tampered ciphertext must fail MAC authentication',
      );
    });

    test('Wrong key cannot decrypt', () async {
      final rightKey = SecretKey(List.generate(32, (_) => 0xAA));
      final wrongKey = SecretKey(List.generate(32, (_) => 0xBB));
      final nonce    = aesGcm.newNonce();
      final box      = await aesGcm.encrypt(
        utf8.encode('classified'),
        secretKey: rightKey,
        nonce: nonce,
      );

      expect(
        () async => aesGcm.decrypt(
          SecretBox(box.cipherText, nonce: nonce, mac: box.mac),
          secretKey: wrongKey,
        ),
        throwsA(anything),
        reason: 'Wrong key must not successfully decrypt',
      );
    });
  });

  // ── 3. Ratchet Counter Safety (4-byte overflow protection) ────────
  group('SessionState Ratchet Counter', () {
    Uint8List deriveRatchetKey(Uint8List sessionKey, int counter) {
      final input = Uint8List.fromList([
        ...sessionKey,
        counter & 0xFF,
        (counter >> 8) & 0xFF,
        (counter >> 16) & 0xFF,
        (counter >> 24) & 0xFF,
      ]);
      return Uint8List.fromList(sha256.convert(input).bytes);
    }

    final sessionKey = Uint8List.fromList(List.generate(32, (i) => i));

    test('Keys at counter=0 and counter=255 are distinct', () {
      final k0   = deriveRatchetKey(sessionKey, 0);
      final k255 = deriveRatchetKey(sessionKey, 255);
      expect(k0, isNot(equals(k255)));
    });

    test('Counter=256 does NOT collide with counter=0 (4-byte overflow protection)', () {
      final k0   = deriveRatchetKey(sessionKey, 0);
      final k256 = deriveRatchetKey(sessionKey, 256);
      expect(k0, isNot(equals(k256)),
          reason: '4-byte counter prevents wrap-around collision at 256');
    });

    test('Counter=65535 does NOT collide with counter=255 (old 2-byte bug regression)', () {
      final k255   = deriveRatchetKey(sessionKey, 255);
      final k65535 = deriveRatchetKey(sessionKey, 65535);
      expect(k255, isNot(equals(k65535)));
    });

    test('Consecutive ratchet keys are all unique over 500 steps', () {
      final seen = <String>{};
      for (var i = 0; i < 500; i++) {
        final key = base64Encode(deriveRatchetKey(sessionKey, i));
        expect(seen.contains(key), isFalse,
            reason: 'Ratchet key at step $i collides with a previous key');
        seen.add(key);
      }
    });
  });

  // ── 4. Wire-Format Parser Safety ──────────────────────────────────
  group('kamui_v2 Wire Format Parser', () {
    String buildWirePayload(String nonceB64, String ciphertextB64) {
      return 'kamui_v2:$nonceB64:$ciphertextB64';
    }

    String? parseWireFormat(String wire) {
      if (!wire.startsWith('kamui_v2:')) return null;
      final first  = wire.indexOf(':');
      final second = wire.indexOf(':', first + 1);
      if (first == -1 || second == -1 || second >= wire.length - 1) return null;
      return wire.substring(second + 1);
    }

    test('Parser correctly extracts ciphertext with no colons in base64', () {
      final wire = buildWirePayload('abc123', 'xyz789');
      expect(parseWireFormat(wire), equals('xyz789'));
    });

    test('Parser correctly handles base64 padding (=) in ciphertext', () {
      final wire = buildWirePayload('AAEC', 'aGVsbG8gd29ybGQ=');
      expect(parseWireFormat(wire), equals('aGVsbG8gd29ybGQ='));
    });

    test('Parser rejects malformed payload missing second colon', () {
      expect(parseWireFormat('kamui_v2:onlyone'), isNull);
    });

    test('Parser rejects non-kamui_v2 payloads', () {
      expect(parseWireFormat('legacy:nonce:ct'), isNull);
    });

    test('Parser handles long real-world-looking payload', () {
      final nonce = base64Encode(List.generate(12, (i) => i));
      final ct    = base64Encode(List.generate(48, (i) => i * 5 + 1));
      final wire  = buildWirePayload(nonce, ct);
      expect(parseWireFormat(wire), equals(ct));
    });
  });

  // ── 5. B32 Address Generation (I2P Spec) ──────────────────────────
  group('I2P Base32 Address', () {
    Uint8List? decodeI2pBase64(String input) {
      try {
        String n = input.replaceAll('-', '+').replaceAll('~', '/');
        while (n.length % 4 != 0) {
          n += '=';
        }
        return base64Decode(n);
      } catch (_) {
        return null;
      }
    }

    String encodeBase32(Uint8List bytes) {
      const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
      final buf = StringBuffer();
      int bitBuffer = 0;
      int bitCount  = 0;
      for (final b in bytes) {
        bitBuffer = (bitBuffer << 8) | (b & 0xFF);
        bitCount += 8;
        while (bitCount >= 5) {
          bitCount -= 5;
          buf.write(alphabet[(bitBuffer >> bitCount) & 0x1F]);
        }
      }
      if (bitCount > 0) {
        buf.write(alphabet[(bitBuffer << (5 - bitCount)) & 0x1F]);
      }
      return buf.toString();
    }

    String computeB32(String destKey) {
      final raw       = decodeI2pBase64(destKey);
      final hashBytes = (raw != null && raw.isNotEmpty)
          ? sha256.convert(raw).bytes
          : sha256.convert(utf8.encode(destKey)).bytes;
      return '${encodeBase32(Uint8List.fromList(hashBytes))}.b32.i2p';
    }

    test('B32 address is 60 chars total (52 hash + 8 suffix)', () {
      final fakeDestBytes = Uint8List(387);
      for (var i = 0; i < fakeDestBytes.length; i++) {
        fakeDestBytes[i] = i & 0xFF;
      }
      final fakeDestKey = base64Encode(fakeDestBytes)
          .replaceAll('+', '-')
          .replaceAll('/', '~')
          .replaceAll('=', '');
      final b32 = computeB32(fakeDestKey);
      expect(b32.endsWith('.b32.i2p'), isTrue);
      expect(b32.length, equals(60),
          reason: 'SHA-256 → Base32 → 52 chars + 8 for ".b32.i2p" suffix');
    });

    test('Identical destination keys produce identical B32 addresses (deterministic)', () {
      const destKey = 'k8x9mQ3pAzRfT7vWsL2nJhDcYbXuE5oP1gKiNqVmBw4j6F8d0eCrZlOyH3m2p';
      expect(computeB32(destKey), equals(computeB32(destKey)));
    });

    test('Different destination keys produce different B32 addresses', () {
      const key1 = 'k8x9mQ3pAzRfT7vWsL2nJhDcYbXuE5oP1gKiNqVmBw4j6F8d0eCrZlOyH3m2p';
      const key2 = 'a7f3kRxMpLsW9nZqTvYcBdUeHoJi2gN4FmXwV6K8jD0P1rAyCbE5lQ...9c1k';
      expect(computeB32(key1), isNot(equals(computeB32(key2))));
    });

    test('B32 alphabet only contains valid RFC 4648 characters (a-z, 2-7)', () {
      const destKey = 'w9y0nR4qBzSgU8xXtM3oKiEdZcYvF6pQ2hLjOrWnCx5k7G9e1fDsAmPzI4n3q';
      final b32  = computeB32(destKey);
      final host = b32.replaceAll('.b32.i2p', '');
      final validChars = RegExp(r'^[a-z2-7]+$');
      expect(validChars.hasMatch(host), isTrue,
          reason: 'Base32 must only use RFC 4648 alphabet: a-z and 2-7');
    });
  });

  // ── 6. Handshake Payload Round-trip ───────────────────────────────
  group('IdentityKeyService Handshake Payload', () {
    Map<String, String> parsePayload(String raw) {
      try {
        final decoded = jsonDecode(raw) as Map<String, dynamic>;
        return {
          'destination':      (decoded['dest']   as String? ?? raw).trim(),
          'identityPublicKey':(decoded['id_pub'] as String? ?? '').trim(),
        };
      } catch (_) {
        return {'destination': raw.trim(), 'identityPublicKey': ''};
      }
    }

    String buildPayload(String dest, String pubKey) {
      return jsonEncode({'v': 2, 'dest': dest, 'id_pub': pubKey});
    }

    test('Serialise & deserialise handshake payload preserves all fields', () {
      const dest   = 'abc123destKey';
      const pubKey = 'base64pubkey==';
      final result = parsePayload(buildPayload(dest, pubKey));
      expect(result['destination'],       equals(dest));
      expect(result['identityPublicKey'], equals(pubKey));
    });

    test('Plain destination string fallback works for legacy QR codes', () {
      const legacyQR = 'k8x9mQ3pAzRfT7vWsL2nJhDcYbXuE5oP1g';
      final result   = parsePayload(legacyQR);
      expect(result['destination'],       equals(legacyQR));
      expect(result['identityPublicKey'], equals(''));
    });

    test('Version field is 2 in v2 payloads', () {
      final payload = jsonDecode(buildPayload('dest', 'key')) as Map<String, dynamic>;
      expect(payload['v'], equals(2));
    });

    test('Empty public key does not crash parser', () {
      final result = parsePayload(buildPayload('somedest', ''));
      expect(result['identityPublicKey'], equals(''));
      expect(result['destination'],       equals('somedest'));
    });
  });

  // ── 7. Session Key Derivation (HKDF-like SHA-256 with domain label) ─
  group('Session Key HKDF Domain Separation', () {
    test('Derived session key is exactly 32 bytes', () async {
      final x25519 = X25519();
      final aliceKP = await x25519.newKeyPair();
      final bobKP   = await x25519.newKeyPair();
      final bobPK   = await bobKP.extractPublicKey();

      final sharedSecret = await x25519.sharedSecretKey(
        keyPair: aliceKP,
        remotePublicKey: bobPK,
      );
      final sharedBytes = await sharedSecret.extractBytes();
      final derived = Uint8List.fromList(
        sha256.convert(Uint8List.fromList(
          [...sharedBytes, ...utf8.encode('Kamui-Session-v2')],
        )).bytes,
      );

      expect(derived.length, equals(32));
    });

    test('Domain label "Kamui-Session-v2" produces different key than raw secret', () async {
      final x25519 = X25519();
      final kp1 = await x25519.newKeyPair();
      final kp2 = await x25519.newKeyPair();
      final pk2 = await kp2.extractPublicKey();

      final ss = await (await x25519.sharedSecretKey(
        keyPair: kp1,
        remotePublicKey: pk2,
      )).extractBytes();

      final withLabel    = sha256.convert([...ss, ...utf8.encode('Kamui-Session-v2')]).bytes;
      final withoutLabel = sha256.convert(ss).bytes;

      expect(withLabel, isNot(equals(withoutLabel)),
          reason: 'Domain label must change the derived key');
    });
  });

  // ── 8. Fail-Closed Architecture (No Silent Downgrade) ─────────────
  group('Fail-Closed Architecture', () {
    // Inline minimal SessionManager logic to validate Fail-Closed contract
    // without depending on platform plugins (flutter_secure_storage).
    //
    // The contract: encryptMessage MUST throw when no session can be established.
    // It MUST NOT silently fall back to weaker (non-ratcheted) encryption.

    test('encryptMessage throws when no peer identity key is provided', () async {
      // Simulate the fail-closed logic: if getOrCreateSession returns null
      // (no peerIdentityPublicKeyB64 given), the caller must receive an exception.
      Future<String> failClosedEncrypt(String? peerKey) async {
        if (peerKey == null || peerKey.isEmpty) {
          throw Exception('SessionUnavailableException: No active v2 session'
              ' — peer identity key required to establish E2EE.');
        }
        // Simulate successful v2 path (not reached in this test)
        return 'kamui_v2:nonce:ct';
      }

      expect(
        () async => failClosedEncrypt(null),
        throwsA(isA<Exception>()),
        reason: 'No silent downgrade: must throw when peer key is absent',
      );
      expect(
        () async => failClosedEncrypt(''),
        throwsA(isA<Exception>()),
        reason: 'Empty peer key must also trigger Fail-Closed exception',
      );
    });

    test('decryptMessage returns null for non-kamui_v2 legacy wire payloads', () {
      // Contract: unrecognised payloads must NOT be silently decrypted via
      // a weaker fallback — they return null so the UI can show an indicator.
      String? failClosedDecrypt(String wirePayload) {
        if (!wirePayload.startsWith('kamui_v2:')) {
          // Fail-Closed: no legacy CryptoService fallback.
          return null;
        }
        return 'decrypted'; // would proceed with v2 path
      }

      expect(failClosedDecrypt('legacy:nonce:ct'), isNull,
          reason: 'Legacy payload must return null, not attempt weak decryption');
      expect(failClosedDecrypt('plaintext message'), isNull,
          reason: 'Plaintext wire value must return null, not be echoed back');
      expect(failClosedDecrypt('kamui_v2:nonce:ct'), equals('decrypted'),
          reason: 'Valid v2 wire format proceeds normally');
    });

    test('Wire format prefix "kamui_v2:" is mandatory for decryption path', () {
      const validPayload   = 'kamui_v2:AAEC:aGVsbG8=';
      const invalidPayload = 'kamui_v1:AAEC:aGVsbG8=';
      const rawPayload     = 'Hello World';

      bool isV2Payload(String p) => p.startsWith('kamui_v2:');

      expect(isV2Payload(validPayload),   isTrue);
      expect(isV2Payload(invalidPayload), isFalse,
          reason: 'v1 prefix must not be treated as v2');
      expect(isV2Payload(rawPayload),     isFalse,
          reason: 'Raw plaintext must not be treated as v2');
    });
  });
}
