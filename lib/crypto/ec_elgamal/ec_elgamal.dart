import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/ec_elgamal.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/ecc/api.dart';

import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:psifos_mobile_crypto/crypto/ec_elgamal/ec_ciphertext.dart';
import 'package:psifos_mobile_crypto/crypto/ec_elgamal/ec_plaintext.dart';

class ECElGamal {
  static AsymmetricKeyPair generateKeyPair(ECDomainParameters domainParams) {
    // Define key parameters
    final keyParams = ECKeyGeneratorParameters(domainParams);

    // Generate secure random using ChaCha20
    final secureRandom = SecureRandom("Fortuna")
      ..seed(
          KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));

    // Define key parameters with randomness
    final keyParamsWithRandomness =
        ParametersWithRandom(keyParams, secureRandom);

    // Initialize key generator
    final keyGenerator = ECKeyGenerator();
    keyGenerator.init(keyParamsWithRandomness);

    // Generate key pair
    final pair = keyGenerator.generateKeyPair();

    final publicKey = pair.publicKey as ECPublicKey;
    final privateKey = pair.privateKey as ECPrivateKey;
    return AsymmetricKeyPair<ECPublicKey, ECPrivateKey>(publicKey, privateKey);
  }

  static ECCipherText encrypt(ECPublicKey publicKey, ECPlainText plaintText) {
    // Initialize encryptor
    final encryptor = ECElGamalEncryptor();
    encryptor.init(PublicKeyParameter<ECPublicKey>(publicKey));

    // Encrypt plaint text
    ECPair cipherTextPair = encryptor.encrypt(plaintText.point);

    return ECCipherText.fromPair(cipherTextPair);
  }

  static ECPlainText decrypt(ECPrivateKey privateKey, ECCipherText cipherText) {
    // Initialize decryptor
    final decryptor = ECElGamalDecryptor();
    decryptor.init(PrivateKeyParameter<ECPrivateKey>(privateKey));

    // Decrypt cipher text
    ECPoint decryptedPoint = decryptor.decrypt(cipherText.pair);

    return ECPlainText.fromECPoint(
        decryptedPoint, privateKey.parameters!.curve);
  }
}
