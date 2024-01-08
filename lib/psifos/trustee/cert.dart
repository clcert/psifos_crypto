import 'dart:convert';

import 'package:psifos_mobile_crypto/crypto/ecc/ec_dsa/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';
import 'package:psifos_mobile_crypto/crypto/modp/rsa/rsa_keypair/export.dart';

class Certificate {
  static Map<String, dynamic> generateCertificate(
      ECPrivateKey signaturePrivateKey,
      ECPublicKey signaturePublicKey,
      RSAPublicKey encryptionPublicKey) {
    final certificate = {
      'signature_public_key': signaturePublicKey.toJson(),
      'encryption_public_key': encryptionPublicKey.toJson(),
    }.toString();

    final certificateSignature = ECDSA
        .sign(
          signaturePrivateKey,
          utf8.encode(certificate),
        )
        .toJson();

    return {
      'json_encoded_keys': certificate,
      'signature': certificateSignature,
    };
  }
}
