import 'dart:convert';
import 'dart:typed_data';

import 'package:webpush_encryption/webpush.dart';

Future<void> main(List<String> arguments) async {
  var keyz = await WebPushKeys.random();

  //one way of manually importing keys
  keyz = WebPushKeys(
    pubKeyBytes: base64.decode(
        "BGviCUiE9bL6HqxXZRLKb3pmHYGq24acYDoE-Hy2aZM9h2gIx0jrQTWh2ksIaFegv6yUQLkpbV7984w0IpvlT-Y="),
    authKeyBytes: Uint8List(16),
    privKeyBytes: base64Decode(
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQga-gpVIxZJHJ_uUx9ON45Lm5Owp5qbM3o7u0p0qrmoZqhRANCAARr4glIhPWy-h6sV2USym96Zh2BqtuGnGA6BPh8tmmTPYdoCMdI60E1odpLCGhXoL-slEC5KW1e_fOMNCKb5U_m"),
  );
  // this is equivalent to the above key
  assert(keyz ==
      await WebPushKeys.fromBase64(
          "BGviCUiE9bL6HqxXZRLKb3pmHYGq24acYDoE-Hy2aZM9h2gIx0jrQTWh2ksIaFegv6yUQLkpbV7984w0IpvlT-Y=+AAAAAAAAAAAAAAAAAAAAAA==+MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQga-gpVIxZJHJ_uUx9ON45Lm5Owp5qbM3o7u0p0qrmoZqhRANCAARr4glIhPWy-h6sV2USym96Zh2BqtuGnGA6BPh8tmmTPYdoCMdI60E1odpLCGhXoL-slEC5KW1e_fOMNCKb5U_m")); // importing based on storage format

// this is what the WebPush Application Server needs
  print(keyz.pubKeyWeb);
  print(keyz.authWeb);

//these two are equivalent except for the format
  print(keyz.toBase64);
  print(keyz.allKeysRaw);

  //the decrypt method
  print(String.fromCharCodes(
      (await WebPush.decrypt(keyz, Uint8List.fromList(bytes)))));
}

List<int> bytes = [
  27,
  100,
  138,
  108,
  205,
  174,
  43,
  77,
  156,
  207,
  31,
  166,
  34,
  94,
  196,
  48,
  0,
  0,
  16,
  0,
  65,
  4,
  212,
  131,
  148,
  232,
  78,
  42,
  128,
  199,
  141,
  210,
  117,
  62,
  163,
  104,
  1,
  82,
  175,
  199,
  199,
  62,
  174,
  165,
  237,
  129,
  19,
  67,
  135,
  170,
  33,
  37,
  58,
  240,
  209,
  32,
  140,
  195,
  249,
  226,
  138,
  20,
  113,
  23,
  0,
  24,
  104,
  194,
  252,
  142,
  252,
  92,
  91,
  175,
  51,
  65,
  39,
  65,
  117,
  138,
  83,
  17,
  97,
  240,
  69,
  97,
  183,
  180,
  169,
  135,
  138,
  31,
  121,
  23,
  221,
  244,
  254,
  125,
  253,
  236,
  41,
  79,
  36,
  233,
  227
];
