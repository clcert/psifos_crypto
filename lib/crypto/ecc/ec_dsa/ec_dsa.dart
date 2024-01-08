import 'dart:typed_data';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/crypto/ecc/ec_dsa/ec_signature.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';

class ECDSA {
  static ECKeyPair<ECPublicKey, ECPrivateKey> generateKeyPair(
      ecc_api.ECDomainParameters domainParams) {
    return ECKeyGenerator.generateKeyPair(domainParams);
  }

  static ECSignature sign(ECPrivateKey privateKey, Uint8List dataToSign) {
    final digest = SHA256Digest();
    final kMac = HMac.withDigest(digest);
    final signer = ECDSASigner(digest, kMac);

    // initialize with true, which means sign
    signer.init(
        true, PrivateKeyParameter<ecc_api.ECPrivateKey>(privateKey.instance));

    return ECSignature(
        signer.generateSignature(dataToSign) as ecc_api.ECSignature);
  }

  static bool verify(
      ECPublicKey publicKey, Uint8List signedData, ECSignature signature) {
    final digest = SHA256Digest();
    final kMac = HMac.withDigest(digest);
    final verifier = ECDSASigner(digest, kMac);

    // initialize with false, which means verify
    verifier.init(
        false, PublicKeyParameter<ecc_api.ECPublicKey>(publicKey.instance));

    try {
      return verifier.verifySignature(signedData, signature.instance);
    } on ArgumentError {
      return false; // for Pointy Castle 1.0.2 when signature has been modified
    }
  }
}
