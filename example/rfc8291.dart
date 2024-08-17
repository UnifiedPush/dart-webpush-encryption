/// Encrypt and decrypt example from RFC8291.
///
/// https://datatracker.ietf.org/doc/html/rfc8291#section-5
library rfc8291_example;

import 'dart:convert';
import 'dart:typed_data';

import 'package:webpush_encryption/webpush_encryption.dart';

const clearText = 'When I grow up, I want to be a watermelon';
const expectedCipherText =
    'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN';

void main() async {
  final server = WebPushKeySet(
    publicKey: PublicWebPushKey(
      publicKeyBytes: base64Decode(
        'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8=',
      ),
      authKeyBytes: base64Decode('zTpiKCtEyaFCYP0BDNOo8A=='),
    ),
    // Private key was in X9.62 uncompressed and needed to be converted with:
    //   openssl pkcs8 -topk8 -in ec.priv -out my.pkcs8.key -nocrypt
    // private key: yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw
    privateKey: PrivateWebPushKey(
      privateKeyBytes: base64Decode(
        'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyfWPiYE+n46HLnH0KqZOF1fJJU3MYrct3AELtAQ+oRyhRANCAAT+M/SrDepxkU21WCP3O1SUj0EwbZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP',
      ),
    ),
  );

  final uaPrivate = WebPushKeySet(
    publicKey: PublicWebPushKey(
      publicKeyBytes: base64Decode(
        'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4=',
      ),
      authKeyBytes: base64Decode('BTBZMqHH6r4Tts7J_aSIgg=='),
    ),
    // Private key was in X9.62 uncompressed and needed to be converted with:
    //   openssl pkcs8 -topk8 -in ec.priv -out my.pkcs8.key -nocrypt
    // private key: q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94
    privateKey: PrivateWebPushKey(
      privateKeyBytes: base64Decode(
          'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq1dXpw3UpT5VOmu/cf/v6ih07Aems3njxI+JWgLcM96hRANCAAQlcbK+zf3jYFUarx7Q9M02bBHOvlVfiby3sYalMzkXMWjs4uvgGFl70wR5uG48j47O1XfKWRh+kkaZDbaCAIsO'),
    ),
  );

  // What would be sent to the server.
  final uaPublic = PublicWebPushKey(
    publicKeyBytes: base64Decode(
      'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4=',
    ),
    authKeyBytes: base64Decode(
      'BTBZMqHH6r4Tts7J_aSIgg==', // cspell:disable-line
    ),
  );

  final salt = base64Decode(
    'DGv6ra1nlYgDCS1FRnbzlw==', // cspell:disable-line
  );
  final cipherText = await WebPush.encrypt(
      serverKeys: server,
      clientKeys: uaPublic,
      salt: salt,
      plaintext: Uint8List.fromList(clearText.codeUnits));

  final cipherText64 = base64Url.encode(cipherText);

  final plainText =
      String.fromCharCodes(await WebPush.decrypt(uaPrivate, cipherText));
  print('''
RFC8291 Example:
  plainText: $plainText
  cipherText: $cipherText64
  cipherText == expectedCipherText: ${cipherText64 == expectedCipherText}
  text -> encrypt -> decrypt -> text: ${plainText == clearText}
''');
}
