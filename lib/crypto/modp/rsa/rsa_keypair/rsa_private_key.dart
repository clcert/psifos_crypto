import 'package:pointycastle/asymmetric/api.dart' as api;

class RSAPrivateKey {
  api.RSAPrivateKey _rsaPrivateKey;

  // getter for the instance
  get instance => _rsaPrivateKey;

  RSAPrivateKey(this._rsaPrivateKey);

  RSAPrivateKey.fromJson(Map<String, dynamic> json)
      : _rsaPrivateKey = api.RSAPrivateKey(
          BigInt.parse(json['modulus']),
          BigInt.parse(json['privateExponent']),
          BigInt.parse(json['p']),
          BigInt.parse(json['q']),
        );

  Map<String, String> toJson() {
    return {
      'modulus': _rsaPrivateKey.modulus!.toString(),
      'privateExponent': _rsaPrivateKey.privateExponent!.toString(),
      'p': _rsaPrivateKey.p!.toString(),
      'q': _rsaPrivateKey.q!.toString(),
    };
  }
}
