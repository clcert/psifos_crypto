import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/ec_elgamal.dart' as pc_elgamal;
import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';

class ECElGamalEncryptor extends pc_elgamal.ECElGamalEncryptor {
  ecc_api.ECPublicKey? publicKey;

  @override
  ecc_api.ECPair encrypt(ecc_api.ECPoint point, {BigInt? k}) {
    if (k == null) {
      return super.encrypt(point);
    }
    var ec = publicKey!.parameters!;
    return ecc_api.ECPair(
      (ec.G * k)!,
      ((publicKey!.Q! * k)! + point)!,
    );
  }

  @override
  void init(CipherParameters params) {
    PublicKeyParameter<ecc_api.ECPublicKey> publicKeyParameter =
        params as PublicKeyParameter<ecc_api.ECPublicKey>;
    this.publicKey = publicKeyParameter.key;
    super.init(params);
  }
}

class ECElGamal {
  static ECKeyPair<ECPublicKey, ECPrivateKey> generateKeyPair(
      ecc_api.ECDomainParameters domainParams) {
    return ECKeyGenerator.generateKeyPair(domainParams);
  }

  static ECElGamalEncryptor _initEncryptor(ECPublicKey publicKey) {
    final encryptor = ECElGamalEncryptor();
    encryptor.init(PublicKeyParameter<ecc_api.ECPublicKey>(publicKey.instance));
    return encryptor;
  }

  static ecc_api.ECPair encryptECPoint(
      ECPublicKey publicKey, ecc_api.ECPoint point,
      {BigInt? k}) {
    // Initialize encryptor
    final encryptor = _initEncryptor(publicKey);

    // Encrypt point
    return encryptor.encrypt(point, k: k);
  }

  static pc_elgamal.ECElGamalDecryptor _initDecryptor(ECPrivateKey privateKey) {
    final decryptor = pc_elgamal.ECElGamalDecryptor();
    decryptor
        .init(PrivateKeyParameter<ecc_api.ECPrivateKey>(privateKey.instance));
    return decryptor;
  }

  static ecc_api.ECPoint decryptECPair(
      ECPrivateKey privateKey, ecc_api.ECPair pair) {
    // Initialize decryptor
    final decryptor = _initDecryptor(privateKey);

    // Decrypt cipher text
    return decryptor.decrypt(pair);
  }

  static ecc_api.ECPair homomorphicAddition(List<ecc_api.ECPair> pairs) {
    // Addition of ECPairs
    final ecPairAddition = (a, b) => ecc_api.ECPair(a.x + b.x, a.y + b.y);

    // Return the sum of all pairs
    return pairs.reduce(ecPairAddition);
  }
}
