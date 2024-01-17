import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

import 'package:psifos_mobile_crypto/utils/convert.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_dsa/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_tdkg/export.dart';
import 'package:psifos_mobile_crypto/crypto/modp/rsa/export.dart';

class TrusteeSyncStep1 {
  /* Parses step 1 input into usable classes */
  static Map<String, dynamic> parseInput(Map<String, dynamic> input) {
    final domainParams = ECCurve_secp521r1();
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
      ecc_api.ECDomainParameters domainParams,
      int threshold,
      int numParticipants) {
    /* make sure the number of encryption keys is correct */
    assert(encryptionPublicKeys.length == numParticipants);

    /* curve parameters */
    final basePoint = domainParams.G as fp.ECPoint;
    final curveOrder = domainParams.n;

    /* generate the secret, coefficients and broadcasts */
    final secret = ECTDKG.randomScalar(curveOrder);
    final coefficients =
        ECTDKG.generateCoefficients(secret, threshold, curveOrder);
    final broadcasts = ECTDKG.generateBroadcasts(coefficients, basePoint);

    /* sign the broadcasts */
    final signedBroadcasts = broadcasts
        .map((b) => TrusteeSyncStep1._signBroadcast(signaturePrivateKey, b))
        .toList();

    /* calculate, encrypt and sign the shares */
    List<Map<String, dynamic>> signedEncryptedShares = [];
    for (int j = 1; j <= numParticipants; j++) {
      // Participant i calculates a share s_{i,j} for participant j.
      BigInt share =
          ECTDKG.calculateShare(BigInt.from(j), coefficients, curveOrder);

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
      "signed_broadcasts": signedBroadcasts,
      "signed_shares": signedEncryptedShares,
    };
  }

  /* Signs a broadcast */
  static Map<String, dynamic> _signBroadcast(
      ECPrivateKey privateKey, ecc_api.ECPoint broadcast) {
    String broadcastStr = broadcast.toString();
    Uint8List broadcastBytes = Uint8List.fromList(utf8.encode(broadcastStr));
    ECSignature broadcastSignature = ECDSA.sign(privateKey, broadcastBytes);

    return {
      "broadcast": broadcastStr,
      "signature": broadcastSignature.toJson(),
    };
  }
}
