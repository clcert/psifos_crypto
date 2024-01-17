import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:psifos_mobile_crypto/crypto/ecc/ec_dsa/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_tdkg/export.dart';
import 'package:psifos_mobile_crypto/crypto/modp/rsa/export.dart';
import 'package:psifos_mobile_crypto/utils/convert.dart';

class TrusteeSyncStep2 {
  /* Parses step 2 input into usable classes */
  static Map<String, dynamic> parseInput(Map<String, dynamic> keyPairs,
      Map<String, dynamic> certificates, Map<String, dynamic> input) {
    final domainParams = ECCurve_secp521r1();

    /* parse private keys from keypair */
    final encryptionPrivateKey =
        RSAPrivateKey.fromJson(keyPairs['encryption']['private_key']);
    final signaturePrivateKey = ECPrivateKey.fromJson(
        keyPairs['signature']['private_key'], domainParams);

    /* parse signature keys from certificates*/
    List<ECPublicKey> signaturePublicKeys = [];
    for (final certJson in certificates["certificates"]) {
      /* No need to verify certificate signature, already done in step 1 */
      signaturePublicKeys.add(
          ECPublicKey.fromJson(certJson["signature_public_key"], domainParams));
    }

    /* parse the signed encrypted shares */
    final signedEncryptedShares = input['signed_encrypted_shares'];

    /* parse the signed broadcasts */
    final signedBroadcasts = input['signed_broadcasts'];

    return {
      'encryption_private_key': encryptionPrivateKey,
      'signature_private_key': signaturePrivateKey,
      'signature_public_keys': signaturePublicKeys,
      'signed_encrypted_shares': signedEncryptedShares,
      'signed_broadcasts': signedBroadcasts,
    };
  }

  static Map<String, dynamic> handle(
      RSAPrivateKey encryptionPrivateKey,
      ECPrivateKey signaturePrivateKey,
      List<ECPublicKey> signaturePublicKeys,
      List<dynamic> signedEncryptedShares,
      List<dynamic> signedBroadcasts,
      int threshold,
      int numParticipants,
      int participantId) {
    /* make sure data is received from the correct number of participants */
    assert(signaturePublicKeys.length == numParticipants);
    assert(signedEncryptedShares.length == numParticipants);
    assert(signedBroadcasts.length == numParticipants);

    /* curve parameters */
    final domainParams = ECCurve_secp521r1();
    final basePoint = domainParams.G as fp.ECPoint;
    final curveOrder = domainParams.n;

    List<Map<String, dynamic>> acknowledgements = [];
    List<BigInt> validShares = [];
    for (int j = 1; j <= numParticipants; j++) {
      final participantSignatureKey = signaturePublicKeys[j - 1];
      final participantSignedEncryptedShare = signedEncryptedShares[j - 1];
      final participantSignedBroadcasts = signedBroadcasts[j - 1];

      /* verify the encrypted share signature */
      BigInt encryptedShare =
          BigInt.parse(participantSignedEncryptedShare['encrypted_share']);
      ECSignature shareSignature =
          ECSignature.fromJson(participantSignedEncryptedShare['signature']);
      final encryptedShareBytes = Convert.fromBigIntToUint8List(encryptedShare);
      final verified = ECDSA.verify(
          participantSignatureKey, encryptedShareBytes, shareSignature);
      if (!verified) {
        throw Exception('Share signature could not be verified.');
      }

      /* decrypt the share */
      final decryptedShareBytes =
          RSA.decrypt(encryptionPrivateKey, encryptedShareBytes);
      BigInt decryptedShare =
          Convert.fromUint8ListToBigInt(decryptedShareBytes);

      /* verify the broadcasts signatures */
      List<ecc_api.ECPoint> broadcasts = [];
      for (Map<String, dynamic> signedBroadcast
          in participantSignedBroadcasts) {
        /* get broadcast and signature */
        ecc_api.ECPoint broadcast = signedBroadcast['broadcast'];
        ECSignature signature = signedBroadcast['signature'] as ECSignature;

        /* broadcast as bytes */
        final broadcastBytes =
            Uint8List.fromList(utf8.encode(broadcast.toString()));
        final verified =
            ECDSA.verify(participantSignatureKey, broadcastBytes, signature);
        if (!verified) {
          throw Exception('Broadcast signature could not be verified.');
        }
        broadcasts.add(signedBroadcast['broadcast']);
      }

      /* validate the share */
      ECSignature ack;
      final valid = ECTDKG.validateShare(
          BigInt.from(j), decryptedShare, broadcasts, basePoint, curveOrder);
      if (valid) {
        validShares.add(decryptedShare);
        ack = ECDSA.sign(signaturePrivateKey,
            Uint8List.fromList("${participantId}|${j}".codeUnits));
      } else {
        ack = ECDSA.sign(signaturePrivateKey, Uint8List.fromList([0]));
      }
      acknowledgements.add(ack.toJson());
    }
    return {
      "acknowledgements": acknowledgements,
      "valid_shares": validShares,
    };
  }
}
