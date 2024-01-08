import 'dart:typed_data';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/utils/convert.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';

class ECTDKG {
  static BigInt randomScalar(BigInt curveOrder) {
    /*
      Returns a random scalar in the range [1, curveOrder).
      This function is used to generate a secret and coefficients
      for the polynomial.
    */
    final secureRandom = SecureRandom("Fortuna")
      ..seed(
          KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));
    final int bytesLen = (curveOrder.bitLength + 7) ~/ 8;
    final Uint8List randomBytes = Uint8List(bytesLen);

    BigInt randomInt;
    do {
      for (int i = 0; i < bytesLen; i++) {
        randomBytes[i] = secureRandom.nextUint8();
      }
      randomInt = Convert.fromUint8ListToBigInt(randomBytes);
    } while (randomInt < BigInt.one || randomInt >= curveOrder);

    return randomInt;
  }

  static List<BigInt> generateCoefficients(
      BigInt secret, int threshold, BigInt curveOrder) {
    /*
      returns t coefficients [a_{0}, ..., a_{t-1}]
      a_{0}: secret
    */
    List<BigInt> coeffs = [secret];
    for (int k = 0; k < threshold - 1; k++) {
      coeffs.add(randomScalar(curveOrder));
    }
    return coeffs;
  }

  static BigInt calculateShare(
      BigInt j, List<BigInt> coefficients, BigInt curveOrder) {
    /*
    Participant i calculates a share s_{i,j} for participant j.
    This function is called by participant i. The share is calculated
    by evaluating the polynomial f(x) at x=j:

    f(x) = a_{0} + a_{1} * j + ... + a_{t-1} * j^(t-1) mod n
    t coefficients, t-1 degree polynomial
    n: curve order
    a0: secret
    j: receiver index
    */

    BigInt share = BigInt.zero;
    for (int exp = 0; exp < coefficients.length; exp++) {
      BigInt coeff = coefficients[exp];
      BigInt expTerm = j.modPow(BigInt.from(exp), curveOrder);
      BigInt mulTerm = (coeff * expTerm) % curveOrder;
      share = (share + mulTerm) % curveOrder;
    }
    return share % curveOrder;
  }

  static List<ecc_api.ECPoint> generateBroadcasts(
    List<BigInt> coefficients,
    ecc_api.ECPoint basePoint,
  ) {
    return coefficients.map((BigInt coeff) => (basePoint * coeff)!).toList();
  }

  static bool validateShare(
      BigInt j,
      BigInt share,
      List<ecc_api.ECPoint> broadcasts,
      ecc_api.ECPoint basePoint,
      BigInt curveOrder) {
    /*
      Participant j recieves a share s_{i,j} and a set of broadcasts
      [A_{i,0}, ..., A_{i,t-1}] from participant i. This function
      must be called by participant j to validate the share s_{i,j}.

      For a share to be valid, the sum of the broadcasts must be
      equal to the base point multiplied by the share:

      >>> rightSide = A_{i,0} + A_{i,1} * j + ... + A_{i,t-1} * j^(t-1)
      >>> leftSide = share * G
      >>> valid if: leftSide == rightSide
    */

    ecc_api.ECPoint rightSide = broadcasts[0];
    for (int exp = 1; exp < broadcasts.length; exp++) {
      ecc_api.ECPoint broadcast = broadcasts[exp];
      BigInt scalar = j.modPow(BigInt.from(exp), curveOrder);
      rightSide = (rightSide + (broadcast * scalar))!;
    }

    ecc_api.ECPoint leftSide = (basePoint * share)!;

    return leftSide == rightSide;
  }

  static BigInt calculateShareSecret(List<BigInt> recv_shares) {
    /*
      Participant i calculates the secret by summing the shares
      received from all participants:

      n: number of participants
      i: participant index
      secret = s_{i,1} + s_{i,2} + ... + s_{i,n}
    */
    return recv_shares.reduce((a, b) => a + b);
  }

  static ecc_api.ECPoint calculateVerificationKey(
      BigInt secret, ecc_api.ECPoint basePoint) {
    /* 
      Participant i calculates the verification key by multiplying
      the base point by the secret:

      verification_key = secret * G
    */
    return (basePoint * secret)!;
  }
}
