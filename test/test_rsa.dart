import 'dart:convert';
import 'package:test/test.dart';

import 'package:psifos_mobile_crypto/crypto/modp/rsa/export.dart';

void main() {
  test('Test RSA', () {
    final message = "Hello, world";
    final messageBytes = utf8.encode(message);
    final bitLength = 2048;

    final keyPair = RSA.generateKeyPair(bitLength: bitLength);

    // print keyPair as JSON
    print(keyPair.privateKey.toJson());
    print(keyPair.publicKey.toJson());

    final cipherText = RSA.encrypt(keyPair.publicKey, messageBytes);
    final retrievedMessageBytes = RSA.decrypt(keyPair.privateKey, cipherText);
    final retrievedMessage = utf8.decode(retrievedMessageBytes);

    assert(retrievedMessage == message);
  });
}
