import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:psifos_mobile_crypto/crypto/ec_elgamal/ec_elgamal.dart';
import 'package:psifos_mobile_crypto/crypto/ec_elgamal/ec_plaintext.dart';
import 'package:test/test.dart';

void main() {
  test('Test ECElGamal', () {
    final message = "Hello, world!";
    final domainParams = ECCurve_secp521r1();
    final plainText = ECPlainText.fromString(message, domainParams.curve);

    final keyPair = ECElGamal.generateKeyPair(domainParams);
    final publicKey = keyPair.publicKey as ECPublicKey;
    final privateKey = keyPair.privateKey as ECPrivateKey;

    final cipherText = ECElGamal.encrypt(publicKey, plainText);

    final retrievedPlainText = ECElGamal.decrypt(privateKey, cipherText);
    assert(retrievedPlainText.text == message);
  });
}
