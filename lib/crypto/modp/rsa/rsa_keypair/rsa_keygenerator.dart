import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';

import 'package:pointycastle/asymmetric/api.dart' as rsa_api;
import 'package:pointycastle/key_generators/rsa_key_generator.dart'
    as rsa_keygen_api;

import 'package:psifos_mobile_crypto/crypto/modp/rsa/rsa_keypair/rsa_keypair.dart';
import 'package:psifos_mobile_crypto/crypto/modp/rsa/rsa_keypair/rsa_public_key.dart';
import 'package:psifos_mobile_crypto/crypto/modp/rsa/rsa_keypair/rsa_private_key.dart';

class RSAKeyGenerator {
  static RSAKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair(
      {int bitLength = 2048}) {
    // Define key parameters
    final keyParams =
        RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64);

    // Generate secure random using Fortuna
    final secureRandom = SecureRandom("Fortuna")
      ..seed(
          KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));

    // Define key parameters with randomness
    final keyParamsWithRandomness =
        ParametersWithRandom(keyParams, secureRandom);

    // Initialize key generator
    final keyGenerator = rsa_keygen_api.RSAKeyGenerator();
    keyGenerator.init(keyParamsWithRandomness);

    // Generate key pair
    final pair = keyGenerator.generateKeyPair();

    final publicKey = RSAPublicKey(pair.publicKey as rsa_api.RSAPublicKey);
    final privateKey = RSAPrivateKey(pair.privateKey as rsa_api.RSAPrivateKey);

    return RSAKeyPair<RSAPublicKey, RSAPrivateKey>(publicKey, privateKey);
  }
}
