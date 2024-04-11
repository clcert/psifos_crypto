import 'package:test/test.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/export.dart';

void main() {
  test('Test ECElGamal', () {
    final message = "Hello, world";
    final domainParams = ECCurve_secp521r1();
    final plainText = ECPlainText.fromString(message, domainParams.curve);

    final keyPair = ECElGamal.generateKeyPair(domainParams);

    // print keyPair as JSON
    print(keyPair.privateKey.toJson());
    print(keyPair.publicKey.toJson());

    final cipherText = ECElGamal.encryptPlainText(keyPair.publicKey, plainText);

    final retrievedPlainText =
        ECElGamal.decryptCipherText(keyPair.privateKey, cipherText);
    assert(retrievedPlainText.text == message);
  });
}
