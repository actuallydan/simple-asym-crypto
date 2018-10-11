# Simple Asymmetric Crypto

  Lazy convenience wrapper around browser crypto API for asymmetric encryption with 2048 RSA

## Installation
```
npm install simple-asym-crypto
```

```javascript
import {pair, encrypt, decrypt} from "simple-asym-crypto";
```

## Use

Asymmetric cryptography is a hugely complex and well-discussed topic, this is simply a convenient wrapper around the browser's native `crypto` API with some opinionated configuration. 

SAC (simple-asym-crypto) uses RSA 2048 to generate a public/private key pair with `pair()`

```javascript
let keys = await pair();
console.log(keys) // {pub: <superlong string>, priv: <even longer string>}

let encryptedText = await encrypt("This is a secret", keys.pub);
console.log(encryptedText) // gibberish stringified encrypted array

let decryptedText = await decrypt(encryptedText, keys.priv);
console.log(decryptedText) // "This is a secret"

```

