import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/ecc/api.dart';
import 'package:psifos_mobile_crypto/crypto/ec_elgamal/ec_point_converter.dart';

class ECPlainText {
  String _text;
  ECPoint _point;

  // Getters for _text and _point
  String get text => _text;
  ECPoint get point => _point;

  // Constructor from a string
  ECPlainText.fromString(String text, ECCurve curve)
      : _text = text,
        _point = _convertStringToECPoint(text, curve);

  // Constructor from an ECPoint
  ECPlainText.fromECPoint(ECPoint point, ECCurve curve)
      : _point = point,
        _text = _convertECPointToString(point, curve);

  static ECPoint _convertStringToECPoint(String text, ECCurve curve) {
    Uint8List textBytes = Uint8List.fromList(utf8.encode(text));
    return ECPointConverter.fromBytesToECPoint(textBytes, curve);
  }

  static String _convertECPointToString(ECPoint point, ECCurve curve) {
    Uint8List retrievedBytes = ECPointConverter.fromECPointToBytes(point);
    return utf8.decode(retrievedBytes);
  }
}
