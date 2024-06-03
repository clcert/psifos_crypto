import 'package:psifos_mobile_crypto/crypto/ecc/ec_elgamal/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/ec_keypair/export.dart';
import 'package:psifos_mobile_crypto/psifos/election/proofs/export.dart';
import 'package:psifos_mobile_crypto/crypto/ecc/utils/ec_random.dart';

import 'package:pointycastle/ecc/api.dart' as ecc_api;

class EncryptedAnswer {
  /* EncryptedAnswer models the answer received for a closed question, i.e. a question with a fixed number of choices.
   * Within a closed question, the voter can select a number of choices between minSelections and maxSelections.
   * Selecting a choice consists on asigning a binary state to it, where 0 means the choice is not selected and 1 means it is selected.
  */

  final int minSelections; // Minimum number of selections
  final int maxSelections; // Maximum number of selections
  final int totalChoices; // Total number of choices in the question

  // Generated when encrypting the answer
  late int numSelections;
  late ecc_api.ECDomainParameters domainParams;
  late List<ecc_api.ECPoint> selectionStatePlaintexts;
  late List<ecc_api.ECPoint> overallSelectionPlaintexts;
  late List<ecc_api.ECPair> choicesCiphertexts;
  late List<ZeroKnowledgeDisjunctiveProof> individualProofs;
  late List<BigInt> choicesRandomness;
  late ZeroKnowledgeDisjunctiveProof overallProof;

  EncryptedAnswer(
      {required this.minSelections,
      required this.maxSelections,
      required this.totalChoices,
      required this.domainParams}) {
    if (minSelections < 1 || maxSelections < minSelections) {
      throw Exception('Invalid selection bounds');
    }

    if (totalChoices < 1) {
      throw Exception('Invalid number of choices');
    }
  }

  void doEncryption(
      {required List<int> selectedChoices, required ECPublicKey publicKey}) {
    // Check that the number of selected choices is within the bounds
    if (selectedChoices.length != totalChoices) {
      throw Exception('Invalid number of selected choices');
    }

    // Check that the selection states are within the bounds
    if (selectedChoices.any((element) => element < 0 || element > 1)) {
      throw Exception('Invalid selection state');
    }

    // Retrieve the domain parameters from the public key
    domainParams = publicKey.instance.parameters!;

    // Generate the possible selection state plaintexts
    selectionStatePlaintexts = _generatePlainexts();

    // Generate choices randomness
    choicesRandomness = List.generate(
        totalChoices, (index) => ECRandom.randomScalar(domainParams.n));

    // Encrypt the choices
    choicesCiphertexts = List.generate(
        totalChoices,
        (index) => ECElGamal.encryptECPoint(
            publicKey, (domainParams.G * BigInt.from(selectedChoices[index]))!,
            k: choicesRandomness[index]));

    // Generate the individual proofs for each choice
    individualProofs = List.generate(
        totalChoices,
        (index) => ZeroKnowledgeDisjunctiveProof(
            realIndex: selectionStatePlaintexts.indexOf(
                (domainParams.G * BigInt.from(selectedChoices[index]))!),
            plaintexts: selectionStatePlaintexts,
            ciphertext: choicesCiphertexts[index],
            randomness: choicesRandomness[index],
            domainParams: domainParams,
            publicKey: publicKey));

    // Compute the number of selections as the sum of the selected choices
    numSelections = selectedChoices.reduce((value, element) => value + element);

    // Check that the number of selections is within the bounds
    if (numSelections < minSelections || numSelections > maxSelections) {
      throw Exception('Invalid number of selections');
    }

    // Generate the possible overall selection plaintexts
    overallSelectionPlaintexts = _generatePlainexts(
        numPlaintexts: maxSelections - minSelections + 1,
        offset: minSelections);

    // Generate the overall proof
    ecc_api.ECPair overallCiphertext =
        ECElGamal.homomorphicAddition(choicesCiphertexts);
    BigInt overallRandomness =
        choicesRandomness.reduce((value, element) => value + element) %
            domainParams.n;
    overallProof = ZeroKnowledgeDisjunctiveProof(
        realIndex: overallSelectionPlaintexts
            .indexOf((domainParams.G * BigInt.from(numSelections))!),
        plaintexts: overallSelectionPlaintexts,
        ciphertext: overallCiphertext,
        randomness: overallRandomness,
        domainParams: domainParams,
        publicKey: publicKey);
  }

  bool verify() {
    // Verify the individual proofs
    bool individualProofsValid =
        individualProofs.every((element) => element.verify() == true);

    // Verify the overall proof
    bool overallProofValid = overallProof.verify();

    return individualProofsValid && overallProofValid;
  }

  List<ecc_api.ECPoint> _generatePlainexts(
      {int numPlaintexts = 2, int offset = 0}) {
    return List.generate(numPlaintexts,
        (index) => (domainParams.G * BigInt.from(index + offset))!);
  }
}
