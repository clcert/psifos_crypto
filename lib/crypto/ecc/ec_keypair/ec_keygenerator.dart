import 'package:pointycastle/api.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:pointycastle/key_generators/api.dart';

import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:pointycastle/key_generators/ec_key_generator.dart'
    as ecc_keygen_api;
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_keypair.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_public_key.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_private_key.dart';

class ECKeyGenerator {
  static ECKeyPair<ECPublicKey, ECPrivateKey> generateKeyPair(
      ecc_api.ECDomainParameters domainParams) {
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
    final keyGenerator = ecc_keygen_api.ECKeyGenerator();
    keyGenerator.init(keyParamsWithRandomness);

    // Generate key pair
    final pair = keyGenerator.generateKeyPair();

    final publicKey = ECPublicKey(pair.publicKey as ecc_api.ECPublicKey);
    final privateKey = ECPrivateKey(pair.privateKey as ecc_api.ECPrivateKey);
    return ECKeyPair<ECPublicKey, ECPrivateKey>(publicKey, privateKey);
  }
}
