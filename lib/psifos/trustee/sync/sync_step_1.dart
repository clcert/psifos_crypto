import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

import 'package:psifos_mobile_crypto/crypto/ecc/ec_dsa/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_tdkg/export.dart';
import 'package:psifos_mobile_crypto/crypto/modp/rsa/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/utils/export.dart';
import 'package:psifos_mobile_crypto/crypto/utils/export.dart';

class TrusteeSyncStep1 {
  /* Parses step 1 input into usable classes */
  static Map<String, dynamic> parseInput(
      Map<String, dynamic> input, String curveName) {
    final domainParams = ecc_api.ECDomainParameters(curveName);
    List<RSAPublicKey> encryptionPublicKeys = [];

    for (final certJson in input["certificates"]) {
      /* Verify certificate signature */
      final signature = ECSignature.fromJson(certJson["signature"]);

      final certificate = json.encode({
        'signature_public_key': certJson["signature_public_key"],
        'encryption_public_key': certJson["encryption_public_key"],
      });

      final signaturePublicKey =
          ECPublicKey.fromJson(certJson["signature_public_key"], domainParams);

      final isValid =
          ECDSA.verify(signaturePublicKey, utf8.encode(certificate), signature);

      if (isValid) {
        encryptionPublicKeys
            .add(RSAPublicKey.fromJson(certJson["encryption_public_key"]));
      } else {
        throw Exception("Invalid certificate signature");
      }
    }
    return {
      "encryption_public_keys": encryptionPublicKeys,
    };
  }

  /* Handles step 1 of the sync protocol */
  static Map<String, dynamic> handle(
      ECPrivateKey signaturePrivateKey,
      List<RSAPublicKey> encryptionPublicKeys,
      String curveName,
      int threshold,
      int numParticipants) {
    /* make sure the number of encryption keys is correct */
    assert(encryptionPublicKeys.length == numParticipants);

    /* curve parameters */
    final domainParams = ecc_api.ECDomainParameters(curveName);
    final basePoint = domainParams.G as fp.ECPoint;
    final curveOrder = domainParams.n;

    /* generate the secret, scalars and coefficients */
    final secret = ECRandom.randomScalar(curveOrder);
    final scalars = ECTDKG.generateScalars(secret, threshold, curveOrder);
    final coefficients = ECTDKG.generateCoefficients(scalars, basePoint);

    /* sign the coefficients */
    final signedCoefficients = coefficients
        .map((b) => TrusteeSyncStep1._signCoefficient(signaturePrivateKey, b))
        .toList();

    /* calculate, encrypt and sign the shares */
    List<Map<String, dynamic>> signedEncryptedShares = [];
    for (int j = 1; j <= numParticipants; j++) {
      // Participant i calculates a share s_{i,j} for participant j.
      BigInt share = ECTDKG.calculateShare(BigInt.from(j), scalars, curveOrder);

      // Participant i encrypts the share s_{i,j} for participant j.
      final publicKey = encryptionPublicKeys[j - 1];
      Uint8List shareBytes = Convert.fromBigIntToUint8List(share);
      Uint8List encryptedShareBytes = RSA.encrypt(publicKey, shareBytes);
      BigInt encryptedShare =
          Convert.fromUint8ListToBigInt(encryptedShareBytes);

      // Participant i signs the encrypted share s_{i,j} for participant j.
      final signature = ECDSA.sign(signaturePrivateKey, encryptedShareBytes);
      signedEncryptedShares.add({
        "encrypted_share": encryptedShare.toString(),
        "signature": signature.toJson()
      });
    }

    return {
      "signed_coefficients": signedCoefficients,
      "signed_shares": signedEncryptedShares,
    };
  }

  /* Signs a coefficient */
  static Map<String, dynamic> _signCoefficient(
      ECPrivateKey privateKey, ecc_api.ECPoint coefficient) {
    String coefficientStr = coefficient.toString();
    Uint8List coefficientBytes =
        Uint8List.fromList(utf8.encode(coefficientStr));
    ECSignature coefficientSignature = ECDSA.sign(privateKey, coefficientBytes);

    return {
      "coefficient": coefficientStr,
      "signature": coefficientSignature.toJson(),
    };
  }
}
