import 'dart:typed_data';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:psifos_mobile_crypto/utils/convert.dart';

class ECPointConverter {
  static int _messagePaddingByteSize = 3;

  static BigInt? _calculateCurveY(BigInt x, ECCurve curve) {
    // Curve equation: y^2 = x^3 + ax + b
    final _curve = curve as fp.ECCurve;
    final a = _curve.a!.toBigInteger()!;
    final b = _curve.b!.toBigInteger()!;
    final q = _curve.q!;

    final x3 = x.modPow(BigInt.from(3), q);
    final ax = (a * x) % q;
    final rhs = (x3 + ax + b) % q;
    final y = rhs.modPow((q + BigInt.one) >> 2, q);

    // This should be verified
    if ((y * y) % q != rhs) {
      return null;
    }
    return y;
  }

  static Uint8List fromECPointToBytes(ECPoint point) {
    // Retrieve the original message from the point
    final pointBigInt = point.x!.toBigInteger()!;

    // xBytes = message || 0xff || counter
    final xBytes = Convert.fromBigIntToUint8List(pointBigInt);

    return xBytes.sublist(0, xBytes.length - _messagePaddingByteSize);
  }

  static ECPoint fromBytesToECPoint(Uint8List messageBytes, ECCurve curve) {
    final _curve = curve as fp.ECCurve;
    int _maxMessageByteSize = _curve.q!.bitLength ~/ 8;
    // Ensure the message is not too long for the curve.
    if (messageBytes.length > _maxMessageByteSize) {
      final byteOverflow = messageBytes.length - _maxMessageByteSize;
      throw Exception('messageBytes is $byteOverflow bytes too long.');
    }

    // extendedMessageBytes = messageBytes || 0xff || counter
    Uint8List extendedMessageBytes = Uint8List(messageBytes.length + 3)
      ..setAll(0, messageBytes)
      ..[messageBytes.length] = 0xff; // Separator byte

    int counter = 0;
    while (true) {
      // Ensure the counter is within the range of 2 bytes
      if (counter > 0xFFFF) {
        throw Exception('Counter has exceeded the range of 2 bytes.');
      }

      // Add the counter to the extended message bytes
      extendedMessageBytes
        ..[messageBytes.length + 1] = (counter >> 8) & 0xFF // High byte
        ..[messageBytes.length + 2] = counter & 0xFF; // Low byte

      final x = Convert.fromUint8ListToBigInt(extendedMessageBytes);
      final y = _calculateCurveY(x, curve);
      if (y != null) {
        return curve.createPoint(x, y);
      } else {
        counter++;
      }
    }
  }
}
