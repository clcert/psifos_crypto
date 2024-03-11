import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/src/ec_standard_curve_constructor.dart';

class ECCParams extends ECDomainParametersImpl {
  factory ECCParams(Map<String, String> params) => constructFpStandardCurve(
        params["name"]!,
        ECCParams._make,
        q: BigInt.parse(params["q"]!, radix: 16),
        a: BigInt.parse(params["a"]!, radix: 16),
        b: BigInt.parse(params["b"]!, radix: 16),
        g: BigInt.parse(params["g"]!, radix: 16),
        n: BigInt.parse(params["n"]!, radix: 16),
        h: BigInt.parse(params["h"]!, radix: 16),
        seed: BigInt.parse(params["seed"]!, radix: 16),
      ) as ECCParams;

  static ECCParams _make(String domainName, ECCurve curve, ECPoint G, BigInt n,
          BigInt _h, List<int> seed) =>
      ECCParams._super(domainName, curve, G, n, _h, seed);

  ECCParams._super(String domainName, ECCurve curve, ECPoint G, BigInt n,
      BigInt _h, List<int> seed)
      : super(domainName, curve, G, n, _h, seed);
}
