import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/ec_elgamal.dart';
import 'package:psifos_mobile_crypto/psifos/election/vote/closed_question/encrypted_answer.dart';
import 'package:test/test.dart';

void main() {
  test('Test ENC ANS', () {
    final domainParams = ECCurve_secp521r1();
    final keyPair = ECElGamal.generateKeyPair(domainParams);

    final encryptedAnswer = EncryptedAnswer(
        minSelections: 1,
        maxSelections: 2,
        totalChoices: 3,
        domainParams: domainParams);

    final selectedChoices = [0, 1, 0];
    encryptedAnswer.doEncryption(
        selectedChoices: selectedChoices, publicKey: keyPair.publicKey);

    final isValid = encryptedAnswer.verify();
    assert(isValid);
  });
}
