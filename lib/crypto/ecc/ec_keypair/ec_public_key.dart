import 'package:pointycastle/ecc/api.dart' as api;

class ECPublicKey {
  api.ECPublicKey _ecPublicKey;

  // getter for _ecPublicKey
  api.ECPublicKey get instance => _ecPublicKey;

  ECPublicKey(this._ecPublicKey);

  ECPublicKey.fromJson(
      Map<String, dynamic> json, api.ECDomainParameters domainParams)
      : _ecPublicKey = api.ECPublicKey(
            domainParams.curve.createPoint(
              BigInt.parse(json['x']),
              BigInt.parse(json['y']),
            ),
            domainParams);

  Map<String, dynamic> toJson() {
    return {
      'x': _ecPublicKey.Q!.x!.toString(),
      'y': _ecPublicKey.Q!.y!.toString(),
    };
  }
}
