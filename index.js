  /*
  * Secret nonce, stored in CF worker settings
  * @param {string}  NONCE
  */ 

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  if (request.method !== 'POST') {
    return new Response('Not found', { status: 404 })
  }
  const url = new URL(request.url)
  const path = url.pathname
  if (path !== '/encrypt' & path !== '/decrypt') {
    return new Response('Not found', { status: 404 })
  }
  const body = await request.json()
  if (path === '/encrypt') return handleEncryptRequest(body)
  if (path === '/decrypt') return handleDecryptRequest(body)
}

async function handleEncryptRequest(body) {
  const now = Date.now().toString()
  const enc = await encrypt(encode(body.text), encode(body.pp), encode(now))
  return new Response(
    JSON.stringify({enc: ab2str(enc), iv: now}),
    {
      headers: {"content-type": "application/json;charset=UTF-8"}
    }
  )
}


async function handleDecryptRequest(body) {
  const dec = await decrypt(str2ab(body.enc), encode(body.pp), encode(body.iv))
  return new Response(
    JSON.stringify({dec: decode(dec)}),
    {
      headers: {"content-type": "application/json;charset=UTF-8"}
    }
  )
}

function encode(str) {
  const encoder = new TextEncoder("utf-8")
  return encoder.encode(str)
}

function decode(buf) {
  const decoder = new TextDecoder("utf-8")
  return decoder.decode(buf)
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}
function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

async function getKeyMaterial() {
  const encoder = new TextEncoder()
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(NONCE),
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );
}

async function deriveKey(salt) {
  const keyMaterial = await getKeyMaterial()
  return crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt: salt,
      "iterations": 100000,
      "hash": "SHA-256"
    },
    keyMaterial,
    { "name": "AES-GCM", "length": 256},
    false,
    [ "encrypt", "decrypt" ]
  )
}

async function encrypt(plaintext, salt, iv) {
  const key = await deriveKey(salt)
  return crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    plaintext
  );
}

async function decrypt(cyphertext, salt, iv) {
  const key = await deriveKey(salt)
  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    cyphertext
  );
}