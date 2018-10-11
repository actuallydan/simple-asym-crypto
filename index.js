
/* 
  Lazy convenience wrapper around browser crypto API for asymmetric encryption with 2048 RSA
  */
async function pair() {
  var crypto = window.crypto || window.msCrypto;

  if (!crypto.subtle) {
    console.error(
      "WebCrypto API not supported! Make sure you're running a modern-enough browser and that you're running this code on HTTPS or in localhost!"
    );
    return;
  }
  return new Promise((resolve, reject) => {
    let promise_key = crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" }
      },
      true,
      ["encrypt", "decrypt"]
    );

    promise_key.then(async function(key) {
      let private_key_object = key.privateKey;
      let public_key_object = key.publicKey;

      let pub = await exportKey(public_key_object);
      let priv = await exportKey(private_key_object);

      resolve({
        pub,
        priv
      });
    });

    promise_key.catch = function(e) {
      reject(e.message);
    };
  });
}

async function exportKey(k) {
  var crypto = window.crypto || window.msCrypto;

  if (!crypto.subtle) {
    console.error(
      "WebCrypto API not supported! Make sure you're running a modern-enough browser and that you're running this code on HTTPS or in localhost!"
    );
    return;
  }
  return JSON.stringify(await crypto.subtle.exportKey("jwk", k));
}

async function encrypt(text, publicKey) {
  var crypto = window.crypto || window.msCrypto;

  if (!crypto.subtle) {
    console.error(
      "WebCrypto API not supported! Make sure you're running a modern-enough browser and that you're running this code on HTTPS or in localhost!"
    );
    return;
  }
  return new Promise(async (resolve, reject) => {
    var vector = crypto.getRandomValues(new Uint8Array(16));
    let public_key_object = await importPubKey(publicKey);
    let encrypt_promise = crypto.subtle.encrypt(
      { name: "RSA-OAEP", iv: vector },
      public_key_object,
      convertStringToArrayBufferView(text)
    );

    encrypt_promise.then(
      function(result) {
        let encrypted_data = new Uint8Array(result);
        resolve(JSON.stringify(encrypted_data));
      },
      function(e) {
        console.error(e.message);
      }
    );
  });
}
function importPrivKey(key) {
  var crypto = window.crypto || window.msCrypto;

  if (!crypto.subtle) {
    console.error(
      "WebCrypto API not supported! Make sure you're running a modern-enough browser and that you're running this code on HTTPS or in localhost!"
    );
    return;
  }
  return new Promise((resolve, reject) => {
    crypto.subtle
      .importKey(
        "jwk",
        JSON.parse(key),
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: "SHA-256" }
        },
        true,
        ["decrypt"]
      )
      .then(
        function(e) {
          console.error(e);
          resolve(e);
        }
      );
  });
}
function importPubKey(key) {
  var crypto = window.crypto || window.msCrypto;

  if (!crypto.subtle) {
    console.error(
      "WebCrypto API not supported! Make sure you're running a modern-enough browser and that you're running this code on HTTPS or in localhost!"
    );
    return;
  }
  return new Promise((resolve, reject) => {
    crypto.subtle
      .importKey(
        "jwk",
        JSON.parse(key),
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: { name: "SHA-256" }
        },
        true,
        ["encrypt"]
      )
      .then(
        function(e) {
          console.log(e);
          resolve(e);
        }
      );
  });
}
function decrypt(encText, privateKey) {
  var crypto = window.crypto || window.msCrypto;

  if (!crypto.subtle) {
    console.error(
      "WebCrypto API not supported! Make sure you're running a modern-enough browser and that you're running this code on HTTPS or in localhost!"
    );
    return;
  }
  return new Promise(async (resolve, reject) => {
    var vector = crypto.getRandomValues(new Uint8Array(16));
    let private_key_object = await importPrivKey(privateKey);

    let decrypt_promise = crypto.subtle.decrypt(
      { name: "RSA-OAEP", iv: vector },
      private_key_object,
      JSON.parse(encText)
    );

    decrypt_promise.then(
      function(result) {
        let decrypted_data = new Uint8Array(result);
        resolve(convertArrayBufferViewtoString(decrypted_data));
      },
      function(e) {
        console.log(e.message);
        reject(e);
      }
    );
  });
}

function convertStringToArrayBufferView(str) {
  var bytes = new Uint8Array(str.length);
  for (var iii = 0; iii < str.length; iii++) {
    bytes[iii] = str.charCodeAt(iii);
  }

  return bytes;
}

function convertArrayBufferViewtoString(buffer) {
  var str = "";
  for (var iii = 0; iii < buffer.byteLength; iii++) {
    str += String.fromCharCode(buffer[iii]);
  }

  return str;
}

module.exports = {
  pair,
  encrypt,
  decrypt
}