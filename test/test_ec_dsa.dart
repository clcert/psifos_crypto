import "dart:convert";
import "dart:typed_data";
import 'package:test/test.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

import 'package:psifos_mobile_crypto/crypto/ecc/ec_dsa/export.dart';

void main() {
  test('Test ECDSA', () {
    final message = "Hello, world!";
    Uint8List messageBytes = Uint8List.fromList(utf8.encode(message));
    final domainParams = ECCurve_secp256k1();

    final keyPair = ECDSA.generateKeyPair(domainParams);

    // print keyPair as JSON
    print(keyPair.privateKey.toJson());
    print(keyPair.publicKey.toJson());

    final signature = ECDSA.sign(keyPair.privateKey, messageBytes);
    final verified = ECDSA.verify(keyPair.publicKey, messageBytes, signature);
    assert(verified == true);
  });
}
