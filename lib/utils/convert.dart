import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:pointycastle/ecc/api.dart' as ecc_api;

class Convert {
  static Uint8List fromBigIntToUint8List(BigInt bigInt) {
    final hexString = bigInt.toRadixString(16);

    // Pad the hexString with 0s if it's not even
    final paddedHexString =
        hexString.length.isEven ? hexString : '0' + hexString;

    return Uint8List.fromList(hex.decode(paddedHexString));
  }

  static BigInt fromUint8ListToBigInt(Uint8List uint8List) {
    return BigInt.parse(hex.encode(uint8List), radix: 16);
  }

  static Map<String, dynamic> fromECPointToJson(ecc_api.ECPoint point) {
    return {
      'x': point.x!.toBigInteger().toString(),
      'y': point.y!.toBigInteger().toString(),
    };
  }
}
