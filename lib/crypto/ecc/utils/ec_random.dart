import 'package:pointycastle/api.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';

class ECRandom {
  static BigInt randomScalar(BigInt curveOrder) {
    /*
    Returns a random scalar in the range [1, curveOrder).
  */
    final secureRandom = SecureRandom("Fortuna")
      ..seed(
          KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));

    // Get the bit length of the order
    int orderBitLength = curveOrder.bitLength;

    // Generate a random integer with the same bit length as the order
    BigInt randomInt;
    do {
      randomInt = secureRandom.nextBigInteger(orderBitLength);
    } while (randomInt >= curveOrder || randomInt <= BigInt.zero);

    return randomInt;
  }
}
