import 'package:pointycastle/ecc/api.dart' as ecc_api;
import 'package:psifos_mobile_crypto/psifos/election/proofs/zkdp.dart';
import 'package:psifos_mobile_crypto/psifos/election/proofs/zkp.dart';
import 'package:psifos_mobile_crypto/psifos/election/vote/closed_question/encrypted_answer.dart';

class Serializer {
  static Map<String, dynamic> fromECPointToJson(ecc_api.ECPoint point) {
    return {
      'x': point.x!.toBigInteger().toString(),
      'y': point.y!.toBigInteger().toString(),
    };
  }

  static Map<String, dynamic> fromCiphertextToJson(ecc_api.ECPair ciphertext) {
    return {
      'alpha': fromECPointToJson(ciphertext.x),
      'beta': fromECPointToJson(ciphertext.y),
    };
  }

  static Map<String, dynamic> fromCommitmentToJson(ecc_api.ECPair commitment) {
    return {
      'A': fromECPointToJson(commitment.x),
      'B': fromECPointToJson(commitment.y),
    };
  }

  static Map<String, dynamic> fromZKPToJson(
      ZeroKnowledgeProof zeroKnowledgeProof) {
    return {
      'challenge': zeroKnowledgeProof.challenge.toString(),
      'response': zeroKnowledgeProof.response.toString(),
      'commitment': fromCiphertextToJson(zeroKnowledgeProof.commitment),
    };
  }

  static List<dynamic> fromZKDPToJson(
      ZeroKnowledgeDisjunctiveProof zeroKnowledgeDisjunctiveProof) {
    return zeroKnowledgeDisjunctiveProof.proofs
        .map((proof) => fromZKPToJson(proof!))
        .toList();
  }

  static Map<String, dynamic> fromEncryptedAnswerToJson(
      EncryptedAnswer answer) {
    return {
      'choices': answer.choicesCiphertexts
          .map((ciphertext) => fromCiphertextToJson(ciphertext))
          .toList(),
      'randomness': answer.choicesRandomness
          .map((randomness) => randomness.toString())
          .toList(),
      'individual_proofs': answer.individualProofs
          .map((proof) => fromZKDPToJson(proof))
          .toList(),
      'overall_proof': fromZKDPToJson(answer.overallProof),
    };
  }
}
