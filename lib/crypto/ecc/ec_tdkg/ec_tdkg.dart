import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/crypto/ecc/utils/export.dart';

class ECTDKG {
  static List<BigInt> generateScalars(
      BigInt secret, int threshold, BigInt curveOrder) {
    /*
      returns t coefficients [a_{0}, ..., a_{t-1}]
      a_{0}: secret
    */
    List<BigInt> scalars = [secret];
    for (int k = 0; k < threshold - 1; k++) {
      scalars.add(ECRandom.randomScalar(curveOrder));
    }
    return scalars;
  }

  static BigInt calculateShare(
      BigInt j, List<BigInt> scalars, BigInt curveOrder) {
    /*
    Participant i calculates a share s_{i,j} for participant j.
    This function is called by participant i. The share is calculated
    by evaluating the polynomial f(x) at x=j:

    f(x) = a_{0} + a_{1} * j + ... + a_{t-1} * j^(t-1) mod n
    t scalars, t-1 degree polynomial
    n: curve order
    a0: secret
    j: receiver index
    */

    BigInt share = BigInt.zero;
    for (int exp = 0; exp < scalars.length; exp++) {
      BigInt coeff = scalars[exp];
      BigInt expTerm = j.modPow(BigInt.from(exp), curveOrder);
      BigInt mulTerm = (coeff * expTerm) % curveOrder;
      share = (share + mulTerm) % curveOrder;
    }
    return share % curveOrder;
  }

  static List<ecc_api.ECPoint> generateCoefficients(
    List<BigInt> scalars,
    ecc_api.ECPoint basePoint,
  ) {
    return scalars.map((BigInt coeff) => (basePoint * coeff)!).toList();
  }

  static bool validateShare(
      BigInt j,
      BigInt share,
      List<ecc_api.ECPoint> coefficients,
      ecc_api.ECPoint basePoint,
      BigInt curveOrder) {
    /*
      Participant j recieves a share s_{i,j} and a set of coefficients
      [A_{i,0}, ..., A_{i,t-1}] from participant i. This function
      must be called by participant j to validate the share s_{i,j}.

      For a share to be valid, the sum of the coefficients multiplied by j
      to the power of the coefficient index must be equal to the base point
      multiplied by the share:

      >>> rightSide = A_{i,0} + A_{i,1} * j + ... + A_{i,t-1} * j^(t-1)
      >>> leftSide = share * G
      >>> valid if: leftSide == rightSide
    */

    ecc_api.ECPoint rightSide = coefficients[0];
    for (int exp = 1; exp < coefficients.length; exp++) {
      ecc_api.ECPoint coefficient = coefficients[exp];
      BigInt scalar = j.modPow(BigInt.from(exp), curveOrder);
      rightSide = (rightSide + (coefficient * scalar))!;
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
