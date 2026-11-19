
### Playing with Ed25519 and BLAKE2b

A small WebAssembly module for digital signatures and hashing in the browser: Ed25519 with BLAKE2b in place of SHA-512, plus plain BLAKE2b. It needs no libc and no JavaScript glue code, it exports a few fixed buffers and five functions.

**Try it:** https://xdsopl.github.io/crypto/ runs the test suite in your browser: known answers, bit flips, the security checks, random keys and messages, and the timings.

---

## 1. Compatibility

The curve, the point and scalar encodings and the key clamping are those of Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)), but every SHA-512 is replaced by BLAKE2b-512. Keys and signatures are therefore **not** compatible with standard Ed25519 libraries, and the RFC 8032 test vectors do not apply.

---

## 2. Scheme

$B$ is the Ed25519 base point and $L = 2^{252} + 27742317777372353535851937790883648493$ its order. Byte strings are concatenated with $\Vert$, and scalars are 32 bytes little endian.

* **Key:** `az` = BLAKE2b-512(`private_key`). The first half is clamped (`az[0] &= 248`, `az[31] &= 127`, `az[31] |= 64`) to the secret scalar $a$. The public key $A = aB$, encoded in 32 bytes, is the `fingerprint`.
* **Sign:** $r = \text{BLAKE2b-512}(az[32..63] \Vert M) \bmod L$, $R = rB$, $h = \text{BLAKE2b-512}(R \Vert A \Vert M) \bmod L$, $S = (r + h a) \bmod L$. The signature is $R \Vert S$, 64 bytes.
* **Verify:** reject unless $S < L$ and $A$ decodes to a point. Accept if the encoding of $SB - hA$ equals $R$ byte for byte.

Signing is deterministic: the same key and message always give the same signature, no randomness is needed after the private key.

---

## 3. Module API

### Buffers
Each buffer is exported as a `WebAssembly.Global` holding its address in `memory`. They are views into the module's memory, so copy the contents out (for example with `slice()`) before the next call overwrites them.

* **`private_key`** (32 bytes): the private key, filled by the caller with 32 random bytes. The module has no random number generator.
* **`fingerprint`** (32 bytes): the public key. Written by `create_fingerprint` and `create_signature`, read by `verify_signature`.
* **`signature`** (64 bytes): written by `create_signature`, read by `verify_signature`.
* **`message`** ($2^{23}$ bytes): the message to sign, verify or hash. Only the first `mlen` bytes are used.
* **`digest`** (64 bytes): the first `dlen` bytes are written by `digest_message`.

### Functions
All functions return `0` on success and `1` on bad arguments.

* **`create_fingerprint()`:** derives `fingerprint` from `private_key`.
* **`create_signature(mlen)`:** signs the first `mlen` bytes of `message` with `private_key` and writes `signature`. It also writes the matching public key to `fingerprint`, replacing whatever was there.
* **`verify_signature(mlen)`:** checks `signature` over the first `mlen` bytes of `message` against `fingerprint`. Returns `0` only for a valid signature, and `1` for an invalid one too.
* **`digest_message(mlen, dlen)`:** writes the BLAKE2b hash with an output length of `dlen` bytes of the first `mlen` bytes of `message` to `digest`. BLAKE2b mixes the output length into the hash, so a 32 byte digest is **not** the first half of the 64 byte digest. Pick one length and stick with it.

### Example
```js
const wasm = (await WebAssembly.instantiateStreaming(fetch("crypto.wasm"))).instance.exports;
const memory = wasm.memory.buffer;
const private_key = new Uint8Array(memory, wasm.private_key.value, 32);
const fingerprint = new Uint8Array(memory, wasm.fingerprint.value, 32);
const signature = new Uint8Array(memory, wasm.signature.value, 64);
const message = new Uint8Array(memory, wasm.message.value, 1 << 23);
const digest = new Uint8Array(memory, wasm.digest.value, 64);

crypto.getRandomValues(private_key);
wasm.create_fingerprint();

const text = new TextEncoder().encode("Hello World!");
message.set(text);
wasm.create_signature(text.length);

if (wasm.verify_signature(text.length) == 0)
	console.log("valid");

wasm.digest_message(text.length, 32);
console.log(digest.slice(0, 32));
```

To verify a signature from somebody else, write their public key into `fingerprint`, their signature into `signature` and the message into `message`, then call `verify_signature(mlen)`.

### Identifiers
Since `verify_signature` rejects $S \ge L$, nobody but the signer can turn a valid signature into a different valid one. The signer can still make as many different signatures of the same message as they like, by choosing a different $r$. So do not identify a signed message by a hash of its signature. Hash the public key and the message instead, for example by copying `fingerprint` and then the message into `message` and calling `digest_message`.

---

## 4. Limits

* **Message length:** $1 \le mlen \le 2^{23}$ bytes. Empty messages are rejected.
* **Digest length:** $1 \le dlen \le 64$ bytes.
* **One thing at a time:** the buffers are fixed and shared by all functions, so a module instance handles one message at a time. Use one instance per worker for parallel work.
* **Memory:** a fixed 131 pages (8.19 MiB) of WebAssembly memory, which never grows.
* **Speed:** in Node.js 22 on a cloud VM, signing a 1000 byte message took about 1.5 ms and verifying it about 2.5 ms.
* **Public keys:** `verify_signature` rejects a `fingerprint` that does not decode to a point, and the 8 small-order points in any encoding. With such a key, one signature would be valid for many messages, and `create_fingerprint` never produces one.
* **Side channels:** the Ed25519 code is the SUPERCOP reference implementation, which passes TIMECOP's constant-time checks as native code (see `ed25519_ref/goal-*`). A WebAssembly engine gives no such guarantee. Verification is variable time, but it only handles public data.
* **Older signatures:** `create_signature` has always written $S < L$, so signatures from earlier versions still verify.

---

## 5. Building

* **`make`:** builds `temp/crypto.wasm` with clang and wasm-ld for `wasm32` and copies it to `docs/crypto.wasm`, which GitHub Pages serves. Commit the rebuilt module together with every change to the code.
* **`make webserver`:** serves `docs/` on http://127.0.0.1:8080/ with Python's `http.server`. `WebAssembly.instantiateStreaming` needs the module served as `application/wasm`, which recent Python versions do. Open it to run the tests against your local build.
* **`make clean`:** removes the object files in `temp/`.

### Layout
* **`module/crypto.c`:** the module itself, built as C89.
* **`ed25519_ref/`:** Ed25519 reference implementation from SUPERCOP.
* **`blake2_ref/`:** BLAKE2 reference implementation.
* **`quirks/`:** the few libc pieces the reference code needs, since the module is built without libc.
* **`docs/`:** the web page and the module for GitHub Pages.

---

## 6. License

Copyright (C) 2024 Ahmet Inan. Released under a permissive license, see [LICENSE](LICENSE). The reference implementations in `ed25519_ref/` and `blake2_ref/` keep their own licenses.
