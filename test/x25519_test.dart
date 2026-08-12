import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('X25519 Diffie-Hellman Key Exchange with cryptography package', () async {
    final algorithm = X25519();

    // Alice generates keypair
    final aliceKeyPair = await algorithm.newKeyPair();
    final alicePublicKey = await aliceKeyPair.extractPublicKey();

    // Bob generates keypair
    final bobKeyPair = await algorithm.newKeyPair();
    final bobPublicKey = await bobKeyPair.extractPublicKey();

    // Alice calculates shared secret with Bob's public key
    final sharedSecretAlice = await algorithm.sharedSecretKey(
      keyPair: aliceKeyPair,
      remotePublicKey: bobPublicKey,
    );

    // Bob calculates shared secret with Alice's public key
    final sharedSecretBob = await algorithm.sharedSecretKey(
      keyPair: bobKeyPair,
      remotePublicKey: alicePublicKey,
    );

    final bytesAlice = await sharedSecretAlice.extractBytes();
    final bytesBob = await sharedSecretBob.extractBytes();

    expect(bytesAlice.length, 32);
    expect(bytesBob.length, 32);
    expect(bytesAlice, equals(bytesBob));
  });
}
