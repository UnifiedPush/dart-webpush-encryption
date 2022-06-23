import 'dart:convert';
import 'dart:typed_data';

import 'package:webpush_encryption/webpush_encryption.dart';
import 'simple.dart' show myPresetMessage;

Future<void> main(List<String> arguments) async {
  var keyz = await WebPushKeys.newKeyPair();

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
      await WebPushKeys.deserialize(
          "BGviCUiE9bL6HqxXZRLKb3pmHYGq24acYDoE-Hy2aZM9h2gIx0jrQTWh2ksIaFegv6yUQLkpbV7984w0IpvlT-Y=+AAAAAAAAAAAAAAAAAAAAAA==+MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQga-gpVIxZJHJ_uUx9ON45Lm5Owp5qbM3o7u0p0qrmoZqhRANCAARr4glIhPWy-h6sV2USym96Zh2BqtuGnGA6BPh8tmmTPYdoCMdI60E1odpLCGhXoL-slEC5KW1e_fOMNCKb5U_m")); // importing based on storage format

// this is what the WebPush Application Server needs
  print(keyz.p256dh);
  print(keyz.auth);

//these two are equivalent except for the format
  print(keyz.serialize);
  print(keyz.rawKeys);

  //the decrypt method
  print(String.fromCharCodes(
      (await WebPush.decrypt(keyz, Uint8List.fromList(myPresetMessage)))));
}
