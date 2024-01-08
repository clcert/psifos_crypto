import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_public_key.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_private_key.dart';

class ECKeyPair<B extends ECPublicKey, V extends ECPrivateKey> {
  final B publicKey;
  final V privateKey;

  ECKeyPair(this.publicKey, this.privateKey);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ECKeyPair &&
          runtimeType == other.runtimeType &&
          publicKey.instance == other.publicKey.instance &&
          privateKey.instance == other.privateKey.instance;

  @override
  int get hashCode =>
      publicKey.instance.hashCode ^ privateKey.instance.hashCode;
}
