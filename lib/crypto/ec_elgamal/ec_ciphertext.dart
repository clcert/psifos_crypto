import 'package:pointycastle/ecc/api.dart';

class ECCipherText {
  ECPair _pair;

  // Getter for _pair
  ECPair get pair => _pair;

  ECCipherText.fromPair(ECPair pair) : _pair = pair;
}
