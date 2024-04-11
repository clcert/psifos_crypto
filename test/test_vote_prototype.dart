import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_public_key.dart';
import 'package:test/test.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/export.dart';

void main() {
  test('Test Vote Prototype', () {
    final domainParams = ECCurve_secp521r1();
    final publicKey = ECPublicKey.fromJson({
      "x":
          "3729495013277543296886905950064070573928957487879679116832130243791954808967122940885117564211430462807323395352820785878558766904401879004570368178226678910",
      "y":
          "2140481129185621138282091950170793421104921210016644751277875908682287455199162458031932300629005624603073618159620318302940878393540244017030950816551964811"
    }, domainParams);
    final vote = [0, 1, 0, 1, 0, 1];
    final encryptedVote = vote.map((v) {
      final optionECPoint = domainParams.G * BigInt.from(v);
      if (v == 0) {
        assert(optionECPoint == domainParams.curve.infinity!);
      } else {
        assert(optionECPoint == domainParams.G);
      }
      return ECElGamal.encryptECPoint(publicKey, optionECPoint!);
    }).toList();

    final homomorphicSum = ECElGamal.homomorphicAddition(encryptedVote);
    print("x: ${homomorphicSum.x}, y: ${homomorphicSum.y}");
  });
}
