import 'package:psifos_mobile_crypto/crypto/modp/rsa/rsa_keypair/rsa_private_key.dart';
import 'package:psifos_mobile_crypto/crypto/modp/rsa/rsa_keypair/rsa_public_key.dart';

class RSAKeyPair<B extends RSAPublicKey, V extends RSAPrivateKey> {
  final B publicKey;
  final V privateKey;

  RSAKeyPair(this.publicKey, this.privateKey);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is RSAKeyPair &&
          runtimeType == other.runtimeType &&
          publicKey.instance == other.publicKey.instance &&
          privateKey.instance == other.privateKey.instance;

  @override
  int get hashCode =>
      publicKey.instance.hashCode ^ privateKey.instance.hashCode;
}
