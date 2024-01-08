import 'package:pointycastle/ecc/api.dart' as api;

class ECSignature {
  api.ECSignature _ecSignature;

  // getter for _ecSignature
  api.ECSignature get instance => _ecSignature;

  ECSignature(this._ecSignature);

  ECSignature.fromJson(Map<String, dynamic> json)
      : _ecSignature = api.ECSignature(
          BigInt.parse(json['r']),
          BigInt.parse(json['s']),
        );

  Map<String, dynamic> toJson() {
    return {
      'r': _ecSignature.r.toString(),
      's': _ecSignature.s.toString(),
    };
  }
}
