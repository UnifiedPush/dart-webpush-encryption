# Dart Webpush encryption library

This library helps facilitate WebPush decryption in Dart. If you just want to receive WebPush notifications on Android in your Flutter app this library is NOT for you, check out the flutter library [`unifiedpush_webpush`](https://github.com/UnifiedPush/flutter-connector-webpush).
This is primarily an RFC 8291 (Message Encryption for Web Push) implementation, however, it implements the same basics as RFC 8188 (Encrypted Content-Encoding for HTTP).

## Usage

See [example/simple.dart](example/simple.dart).

There are 4 main classes here, `WebPushKeySet`, `PublicWebPushKey`, `PrivateWebPushKey`, `WebPush`.

In `WebPushKeySet`:
1. Use `.newKeyPair()` generate a new key pair (private & public).
1. Use `.publicKey` to get the `PublicWebPushKey` of the key set.
1. Use `.serialize` to serialize the public *AND private keys* for storage. **Be careful with this since it contains the private key.**
   Then, use `WebPushKeys.deserialize` to deserialize that back into an object from the stored string.

In `PublicWebPushKey`:
1. Use `.p256dh` and `.auth` to export the keys into the base64 encoding that can be sent to a server.
The `WebPush`class contains two methods:
1. `.decrypt(keys, encryptedBytes)`. Pass in the keys object and an array of Bytes of the message body. It will return the decrypted bytes.
2. `.encrypt(serverKeys, clientPubKey, plaintext, salt?)`: Encrypt the plaintext according to the webpush standard.

> **Warning**
>
> Do not encode the encrypted bytes as a UTF-8 string anywhere between the HTTP request and decryption; UTF-8 encoding will probably mess up your content.

## Installing this package

Add the following to your pubspec.yaml

```yaml
dependencies:
  webpush_encryption: ^1.0.0
```


## Credits

The first version of this was made using [@emersion's code over on sourcehut](https://git.sr.ht/~emersion/goguma/tree/webpush/item/lib/webpush.dart). @emersion gave permission for the code to be relicensed to Apache 2.0 and used in this repo.
