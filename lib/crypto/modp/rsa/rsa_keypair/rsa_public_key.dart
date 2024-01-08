import 'package:pointycastle/asymmetric/api.dart' as api;

class RSAPublicKey {
  api.RSAPublicKey _rsaPublicKey;

  // getter for the instance
  get instance => _rsaPublicKey;

  RSAPublicKey(this._rsaPublicKey);

  RSAPublicKey.fromJson(Map<String, dynamic> json)
      : _rsaPublicKey = api.RSAPublicKey(
          BigInt.parse(json['modulus']),
          BigInt.parse(json['exponent']),
        );

  Map<String, String> toJson() {
    return {
      'modulus': _rsaPublicKey.modulus!.toString(),
      'exponent': _rsaPublicKey.exponent!.toString(),
    };
  }
}
