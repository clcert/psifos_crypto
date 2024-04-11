import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/ec_elgamal.dart';
import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/ec_ciphertext.dart';

import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/ec_plaintext.dart';

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
      ECPublicKey publicKey, ecc_api.ECPoint point) {
    // Initialize encryptor
    final encryptor = _initEncryptor(publicKey);

    // Encrypt point
    return encryptor.encrypt(point);
  }

  static ECCipherText encryptPlainText(
      ECPublicKey publicKey, ECPlainText plaintText) {
    // Retrieve plaintext point and encrypt it
    ecc_api.ECPoint plainTextPoint = plaintText.point;
    ecc_api.ECPair cipherTextPair = encryptECPoint(publicKey, plainTextPoint);

    // Return cipher text
    return ECCipherText.fromPair(cipherTextPair);
  }

  static ECElGamalDecryptor _initDecryptor(ECPrivateKey privateKey) {
    final decryptor = ECElGamalDecryptor();
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

  static ECPlainText decryptCipherText(
      ECPrivateKey privateKey, ECCipherText cipherText) {
    // Retrieve cipher text pair and decrypt it
    ecc_api.ECPair cipherTextPair = cipherText.pair;
    ecc_api.ECPoint plainTextPoint = decryptECPair(privateKey, cipherTextPair);

    // Return plain text
    ecc_api.ECCurve curve = privateKey.instance.parameters!.curve;
    return ECPlainText.fromECPoint(plainTextPoint, curve);
  }

  static ecc_api.ECPair homomorphicAddition(List<ecc_api.ECPair> pairs) {
    // Addition of ECPairs
    final ecPairAddition = (a, b) => ecc_api.ECPair(a.x + b.x, a.y + b.y);

    // Return the sum of all pairs
    return pairs.reduce(ecPairAddition);
  }
}
