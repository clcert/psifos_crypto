import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart' as rsa_api;
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

import 'package:psifos_mobile_crypto/crypto/modp/rsa/rsa_keypair/export.dart';

class RSA {
  static RSAKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair(
      {int bitLength = 2048}) {
    return RSAKeyGenerator.generateKeyPair(bitLength: bitLength);
  }

  static Uint8List encrypt(RSAPublicKey publicKey, Uint8List input) {
    // Initialize encryptor
    final encryptor = OAEPEncoding(RSAEngine())
      ..init(
          true,
          PublicKeyParameter<rsa_api.RSAPublicKey>(
              publicKey.instance)); // true=encrypt

    // Encrypt plaintext
    return _processInBlocks(encryptor, input);
  }

  static Uint8List decrypt(RSAPrivateKey privateKey, Uint8List input) {
    // Initialize decryptor
    final decryptor = OAEPEncoding(RSAEngine())
      ..init(
          false,
          PrivateKeyParameter<rsa_api.RSAPrivateKey>(
              privateKey.instance)); // false=decrypt

    // Decrypt ciphertext
    return _processInBlocks(decryptor, input);
  }

  static Uint8List _processInBlocks(
      AsymmetricBlockCipher engine, Uint8List input) {
    final numBlocks = input.length ~/ engine.inputBlockSize +
        ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

    final output = Uint8List(numBlocks * engine.outputBlockSize);

    var inputOffset = 0;
    var outputOffset = 0;
    while (inputOffset < input.length) {
      final chunkSize = (inputOffset + engine.inputBlockSize <= input.length)
          ? engine.inputBlockSize
          : input.length - inputOffset;

      outputOffset += engine.processBlock(
          input, inputOffset, chunkSize, output, outputOffset);

      inputOffset += chunkSize;
    }

    return (output.length == outputOffset)
        ? output
        : output.sublist(0, outputOffset);
  }
}
