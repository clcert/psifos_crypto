import 'package:psifos_mobile_crypto/psifos/election/proofs/zkdp.dart';
import 'package:test/test.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/utils/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/export.dart';

void main() {
  test('Test ZKDP', () {
    final domainParams = ECCurve_secp521r1();
    final numPlaintexts = 8; // arbitrary number of possible plaintexts
    final realIndex = 1; // arbitrary index of the real plaintext
    final randomness = ECRandom.randomScalar(domainParams.n);

    // Generate the possible plaintexts
    final plaintexts = List.generate(
        numPlaintexts, (index) => (domainParams.G * BigInt.from(index))!);

    // Generate the ciphertext
    final keyPair = ECElGamal.generateKeyPair(domainParams);
    final ciphertext = ECElGamal.encryptECPoint(
        keyPair.publicKey, plaintexts[realIndex],
        k: randomness);

    // Generate the Zero Knowledge Disjunctive Proof
    final disjunctiveProof = ZeroKnowledgeDisjunctiveProof(
      realIndex: realIndex,
      plaintexts: plaintexts,
      ciphertext: ciphertext,
      randomness: randomness,
      domainParams: domainParams,
      publicKey: keyPair.publicKey,
    );

    // Verify the Zero Knowledge Disjunctive Proof
    final isValid = disjunctiveProof.verify();
    assert(isValid);
  });
}
