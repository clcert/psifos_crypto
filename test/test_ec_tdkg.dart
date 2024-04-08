import 'package:test/test.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:pointycastle/ecc/curves/secp256k1.dart';

import 'package:psifos_mobile_crypto/crypto/ecc/ec_tdkg/export.dart';

void main() {
  test('Test ECTDKG', () {
    const int threshold = 3;
    const int numParticipants = 5;

    final domainParams = ECCurve_secp256k1();
    final basePoint = domainParams.G as fp.ECPoint;
    final curveOrder = domainParams.n;

    final secret = ECTDKG.randomScalar(curveOrder);
    final scalars = ECTDKG.generateScalars(secret, threshold, curveOrder);
    final coefficients = ECTDKG.generateCoefficients(scalars, basePoint);

    for (int j = 0; j < numParticipants; j++) {
      // Participant i calculates a share s_{i,j} for participant j.
      final share = ECTDKG.calculateShare(BigInt.from(j), scalars, curveOrder);

      // Participant j validates the share s_{i,j} from participant i.
      final valid = ECTDKG.validateShare(
          BigInt.from(j), share, coefficients, basePoint, curveOrder);

      // Expect the share to be valid.
      expect(valid, true);
    }
  });
}
