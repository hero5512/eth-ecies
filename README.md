Elliptic Curve Integrated Encryption `Scheme` for ethereum secp256k1 in Java.

This is the Java version of ethereum [ecies](https://github.com/ethereum/go-ethereum/tree/master/crypto/ecies) with a built-in class-like secp256k1 API, you may go there for detailed documentation and learn the mechanism under the hood.

## Quick start

```bash
String msg = "hello world";
ECKey key = ECKey.fromPrivate(new BigInteger("40726844782749937894834151007763016161820451265783099183065635627847362290970", 10));
byte[] cipher = ECIES.encrypt(key.getPubKeyPoint(), msg.getBytes(), null, null);
byte[] msgBytes = ECIES.decrypt(((BCECPrivateKey) acc.getPrivateKey()).getD(), cipher, null, acc.serializePublicKey());
```
