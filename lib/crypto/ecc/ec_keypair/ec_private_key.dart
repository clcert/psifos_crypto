import 'package:pointycastle/ecc/api.dart' as api;

class ECPrivateKey {
  api.ECPrivateKey _ecPrivateKey;

  // getter for _ecPrivateKey
  api.ECPrivateKey get instance => _ecPrivateKey;

  ECPrivateKey(this._ecPrivateKey);

  ECPrivateKey.fromJson(
      Map<String, dynamic> json, api.ECDomainParameters domainParams)
      : _ecPrivateKey = api.ECPrivateKey(BigInt.parse(json['d']), domainParams);

  Map<String, dynamic> toJson() {
    return {
      'd': _ecPrivateKey.d.toString(),
    };
  }
}
