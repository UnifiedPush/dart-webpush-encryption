# Dart Webpush encryption library

This library helps facilitate WebPush decryption in Dart. If you just want to receive WebPush notifications on Android in your Flutter app this library is NOT for you, check out the dart library [`unifiedpush_webpush`](https://github.com/UnifiedPush/flutter-connector-webpush).
This is primarily an RFC 8291 (Message Encryption for Web Push) implementation, however, it implements the same basics as RFC 8188 (Encrypted Content-Encoding for HTTP).

## Usage

See example/simple.dart.

There are two main classes here, WebPushKeys, and WebPush.

In WebPush keys:
1. Use `.random()` generate a new key.
1. Use `.pubKeyWeb` and `.authWeb` to export the keys into the base64 encoding that can be sent to a server. `.pubKeyWeb` corresponds to `p256dh` in the spec and `.authWeb` is `auth`.
1. Use `.toBase64` to serialize the public *AND private keys* for storage. Be careful with this since it contains the private key.
   Then, use `WebPushKeys.fromBase64` to unserialize that back into an object from the stored string.

The `WebPush`class contains only one method:
1. `.decrypt(WebPushKeys keys, Uint8List buf)`. Pass in the keys object and an array of Bytes of the message body. It will return the decrypted bytes.

Note: Be careful to not encode the encrypted buffer as a UTF-8 string anywhere between the HTTP request and decryption; UTF-8 encoding will probably mess up your content.


## Credits

The first version of this was made using [@emersion's code over on sourcehut](https://git.sr.ht/~emersion/goguma/tree/webpush/item/lib/webpush.dart). @emersion gave permission for the code to be relicensed to Apache 2.0 and used in this repo.
