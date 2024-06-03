import 'dart:typed_data';

import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/ec_public_key.dart';
import 'package:psifos_mobile_crypto/crypto/utils/convert.dart';
import 'package:psifos_mobile_crypto/psifos/election/proofs/zkp.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/utils/export.dart';

class ZeroKnowledgeDisjunctiveProof {
  final int realIndex;
  final BigInt randomness;

  final List<ecc_api.ECPoint> plaintexts;
  final ecc_api.ECPair ciphertext;
  final ecc_api.ECDomainParameters domainParams;
  final ECPublicKey publicKey;

  late List<ZeroKnowledgeProof?> proofs;

  ZeroKnowledgeDisjunctiveProof(
      {required this.realIndex,
      required this.plaintexts,
      required this.ciphertext,
      required this.randomness,
      required this.domainParams,
      required this.publicKey}) {
    if (realIndex < 0 || realIndex >= plaintexts.length) {
      throw Exception('Index out of bounds');
    }

    // Generate the simulated Zero Knowledge Proofs
    proofs = List.generate(plaintexts.length,
        (index) => index == realIndex ? null : simulateZKP(ptxtIndex: index));

    // Generate the real Zero Knowledge Proof
    proofs[realIndex] = generateZKP();
  }

  ZeroKnowledgeProof simulateZKP({required ptxtIndex}) {
    // Compute the challenge as a random scalar
    BigInt challenge = ECRandom.randomScalar(domainParams.n);

    // Compute the response as a random scalar
    BigInt response = ECRandom.randomScalar(domainParams.n);

    // Compute the commitment (A, B)

    // A = G * response - X * challenge, where X is the first component of the ciphertext (X, Y)
    ecc_api.ECPoint _A_first = (domainParams.G * response)!;
    ecc_api.ECPoint _A_second = (ciphertext.x * challenge)!;
    ecc_api.ECPoint A = (_A_first - _A_second)!;

    // B = Pk * response - (Y - plaintext) * challenge, where Y is the second component of the ciphertext (X, Y)
    ecc_api.ECPoint _B_first = (publicKey.instance.Q! * response)!;
    ecc_api.ECPoint _B_second =
        ((ciphertext.y - plaintexts[ptxtIndex])! * challenge)!;
    ecc_api.ECPoint B = (_B_first - _B_second)!;

    ecc_api.ECPair commitment = ecc_api.ECPair(A, B);

    return ZeroKnowledgeProof(
        challenge: challenge,
        response: response,
        commitment: commitment,
        ptxtIndex: ptxtIndex,
        plaintext: plaintexts[ptxtIndex],
        ciphertext: ciphertext,
        domainParams: domainParams,
        publicKey: publicKey);
  }

  ZeroKnowledgeProof generateZKP() {
    // Compute the commitment (A, B) for the real proof
    BigInt w = ECRandom.randomScalar(domainParams.n);

    ecc_api.ECPoint A = (domainParams.G * w)!; // A = G * w
    ecc_api.ECPoint B = (publicKey.instance.Q! * w)!; // B = Pk * w
    ecc_api.ECPair commitment = ecc_api.ECPair(A, B);

    // Compute the overall challenge of the zkdp using the challenge generator and the commitments of the proofs
    List<ecc_api.ECPair> proofsCommitments = List.generate(plaintexts.length,
        (index) => index == realIndex ? commitment : proofs[index]!.commitment);
    BigInt overallChallenge = _disjunctiveChallengeGenerator(proofsCommitments);

    // Compute the sum of the challenges of the simulated proofs
    List<BigInt> simulatedProofsChallenges = proofs
        .where((proof) => proof != null)
        .map((proof) => proof!.challenge)
        .toList(); // Get the challenges of the simulated proofs
    BigInt sumSimulatedProofsChallenges = simulatedProofsChallenges.fold(
        BigInt.zero,
        (acc, challenge) => (acc + challenge)); // Sum the challenges

    // Compute the real proof challenge as the overall challenge minus the simulated proofs challenges
    BigInt challenge = (overallChallenge - sumSimulatedProofsChallenges) %
        domainParams.n; // Compute the challenge

    // Compute the response as w + challenge * randomness
    BigInt response = w + (challenge * randomness) % domainParams.n;

    return ZeroKnowledgeProof(
        challenge: challenge,
        response: response,
        commitment: commitment,
        ptxtIndex: realIndex,
        plaintext: plaintexts[realIndex],
        ciphertext: ciphertext,
        domainParams: domainParams,
        publicKey: publicKey);
  }

  BigInt _disjunctiveChallengeGenerator(List<ecc_api.ECPair> commitments) {
    // Compute the hash of the commitments
    List<int> hashInput = [];
    for (var commitment in commitments) {
      hashInput.addAll(commitment.x.getEncoded(false));
      hashInput.addAll(commitment.y.getEncoded(false));
    }

    // Compute the hash using SHA1 and parse it as a BigInt
    SHA1Digest sha1 = SHA1Digest();
    Uint8List hash = sha1.process(Uint8List.fromList(hashInput));
    return Convert.fromUint8ListToBigInt(hash) % domainParams.n;
  }

  bool verify() {
    // Verify all proofs
    bool proofsValid =
        proofs.fold(true, (acc, proof) => acc && proof!.verify());

    // Verify the overall challenge
    BigInt overallChallenge = _disjunctiveChallengeGenerator(
        proofs.map((proof) => proof!.commitment).toList());
    BigInt sumChallenges =
        proofs.fold(BigInt.zero, (acc, proof) => acc + proof!.challenge) %
            domainParams.n; // Sum the challenges of the proofs
    bool overallChallengeValid = overallChallenge == sumChallenges;

    if (!overallChallengeValid) {
      throw Exception('Overall challenge is not valid');
    }

    return proofsValid && overallChallengeValid;
  }
}
