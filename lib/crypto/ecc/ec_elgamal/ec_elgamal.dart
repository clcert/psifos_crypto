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

  static ECCipherText encrypt(ECPublicKey publicKey, ECPlainText plaintText) {
    // Initialize encryptor
    final encryptor = ECElGamalEncryptor();
    encryptor.init(PublicKeyParameter<ecc_api.ECPublicKey>(publicKey.instance));

    // Encrypt plaint text
    ecc_api.ECPair cipherTextPair = encryptor.encrypt(plaintText.point);

    return ECCipherText.fromPair(cipherTextPair);
  }

  static ECPlainText decrypt(ECPrivateKey privateKey, ECCipherText cipherText) {
    // Initialize decryptor
    final decryptor = ECElGamalDecryptor();
    decryptor
        .init(PrivateKeyParameter<ecc_api.ECPrivateKey>(privateKey.instance));

    // Decrypt cipher text
    ecc_api.ECPoint decryptedPoint = decryptor.decrypt(cipherText.pair);

    return ECPlainText.fromECPoint(
        decryptedPoint, privateKey.instance.parameters!.curve);
  }
}
