import 'package:pointycastle/asymmetric/api.dart' as api;

extension RSAPublicKey on api.RSAPublicKey {
  Map<String, dynamic> toJson() {
    return {
      'modulus': modulus!.toString(),
      'exponent': exponent!.toString(),
    };
  }

  static api.RSAPublicKey fromJson(Map<String, dynamic> json) {
    return api.RSAPublicKey(
      BigInt.parse(json['modulus']),
      BigInt.parse(json['exponent']),
    );
  }
}

extension RSAPrivateKey on api.RSAPrivateKey {
  Map<String, dynamic> toJson() {
    return {
      'modulus': modulus!.toString(),
      'privateExponent': privateExponent!.toString(),
      'p': p!.toString(),
      'q': q!.toString(),
    };
  }
}
