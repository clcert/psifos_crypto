import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/utils/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/export.dart';

void main() {
  test('Test ECElGamal', () {
    final message = "Hello, world";
    final domainParams = ECCurve_secp521r1();

    // Encode the message as an ECPoint
    final encodedMessage = Uint8List.fromList(utf8.encode(message));
    final plainText =
        ECPointConverter.fromBytesToECPoint(encodedMessage, domainParams.curve);

    // Generate the key pair
    final keyPair = ECElGamal.generateKeyPair(domainParams);

    // Encrypt and decrypt the message
    final cipherText = ECElGamal.encryptECPoint(keyPair.publicKey, plainText);
    final retrievedPlainText =
        ECElGamal.decryptECPair(keyPair.privateKey, cipherText);

    // Decode the message from the ECPoint
    final retrievedBytes =
        ECPointConverter.fromECPointToBytes(retrievedPlainText);
    final retrievedMessage = utf8.decode(retrievedBytes);

    assert(retrievedMessage == message);
  });
}
