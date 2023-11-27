import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

import 'package:pointycastle/src/platform_check/platform_check.dart';

class ECDSA {
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

  static ECSignature sign(ECPrivateKey privateKey, Uint8List dataToSign) {
    final digest = SHA256Digest();
    final kMac = HMac.withDigest(digest);
    final signer = ECDSASigner(digest, kMac);

    // initialize with true, which means sign
    signer.init(true, PrivateKeyParameter<ECPrivateKey>(privateKey));

    return signer.generateSignature(dataToSign) as ECSignature;
  }

  static bool verify(
      ECPublicKey publicKey, Uint8List signedData, ECSignature signature) {
    final digest = SHA256Digest();
    final kMac = HMac.withDigest(digest);
    final verifier = ECDSASigner(digest, kMac);

    // initialize with false, which means verify
    verifier.init(false, PublicKeyParameter<ECPublicKey>(publicKey));

    try {
      return verifier.verifySignature(signedData, signature);
    } on ArgumentError {
      return false; // for Pointy Castle 1.0.2 when signature has been modified
    }
  }
}
