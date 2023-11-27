import "dart:convert";
import "dart:typed_data";

import "package:pointycastle/export.dart";
import "package:psifos_mobile_crypto/crypto/ecdsa/ecdsa.dart";
import "package:test/test.dart";

void main() {
  test('Test ECDSA', () {
    final message = "Hello, world!";
    Uint8List messageBytes = Uint8List.fromList(utf8.encode(message));
    final domainParams = ECCurve_secp256k1();

    final keyPair = ECDSA.generateKeyPair(domainParams);
    final publicKey = keyPair.publicKey as ECPublicKey;
    final privateKey = keyPair.privateKey as ECPrivateKey;

    final signature = ECDSA.sign(privateKey, messageBytes);
    final verified = ECDSA.verify(publicKey, messageBytes, signature);

    assert(verified == true);
  });
}
