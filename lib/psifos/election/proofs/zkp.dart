import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_public_key.dart';

class ZeroKnowledgeProof {
  // Core ZKP components
  final BigInt challenge;
  final BigInt response;
  final ecc_api.ECPair commitment; // commitment = (A, B)

  // Required for verification
  final int ptxtIndex;
  final ecc_api.ECPoint plaintext; // plaintext = G * value
  final ecc_api.ECPair ciphertext; // ciphertext = (X, Y)
  final ecc_api.ECDomainParameters domainParams;
  final ECPublicKey publicKey;

  ZeroKnowledgeProof(
      {required this.challenge,
      required this.response,
      required this.commitment,
      required this.ptxtIndex,
      required this.plaintext,
      required this.ciphertext,
      required this.domainParams,
      required this.publicKey});

  bool verify() {
    // Verify that A == G * response - X * challenge
    ecc_api.ECPoint _A_first = (domainParams.G * response)!;
    ecc_api.ECPoint _A_second = (ciphertext.x * challenge)!;
    ecc_api.ECPoint _A = (_A_first - _A_second)!;
    bool A_is_valid = _A == commitment.x;
    if (!A_is_valid) {
      throw Exception('Invalid proof: A is not valid');
    }

    // Verify that B == Pk * response - (Y - plaintext) * challenge
    ecc_api.ECPoint _B_first = (publicKey.instance.Q! * response)!;
    ecc_api.ECPoint _B_second = ((ciphertext.y - plaintext)! * challenge)!;
    ecc_api.ECPoint _B = (_B_first - _B_second)!;
    bool B_is_valid = _B == commitment.y;
    if (!B_is_valid) {
      throw Exception('Invalid proof: B is not valid');
    }

    return A_is_valid && B_is_valid;
  }
}
