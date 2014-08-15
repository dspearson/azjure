[fips197]: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
[blowfish]: https://www.schneier.com/paper-blowfish-fse.html
[cast256]: http://tools.ietf.org/html/rfc2612
[twofish]: http://www.schneier.com/paper-twofish-paper.pdf
[tea]: http://citeseer.ist.psu.edu/viewdoc/download?doi=10.1.1.45.281&rep=rep1&type=pdf
[xtea]: http://www.cix.co.uk/~klockstone/xtea.pdf
[td]: https://github.com/CraZySacX/azjure/tree/master/spec/azjure
[clojarssvg]: http://clojars.org/azjure/latest-version.svg
[clojars]: http://clojars.org/azjure
[travissvg]: https://travis-ci.org/CraZySacX/azjure.svg?branch=master
[travis]: https://travis-ci.org/CraZySacX/azjure
[cipher]: https://github.com/CraZySacX/azjure/blob/master/src/azjure/cipher/cipher.clj
[encoders]: https://github.com/CraZySacX/azjure/blob/master/src/azjure/encoders.clj
[modes]: https://github.com/CraZySacX/azjure/blob/master/src/azjure/modes.clj
[padders]: https://github.com/CraZySacX/azjure/blob/master/src/azjure/padders.clj
azjure
======

Encryption in Clojure

## Version
[![Clojars Project](clojarssvg)](clojars)

## Status
[![Build Status](travissvg)](travis)

## Project Setup
Add the following in the dependencies section of your project.clj file

```Clojure
:dependencies [...
               [azjure "1.0.0-SNAPSHOT"]
               ...]
```
### Configuration Map
Each function in the API uses map to configure the behavior of the
encrypt/decrypt functions.

The map has the following format:

```clojure
{:type :typekw
 :mode :modekw
 :pad  :padderkw
 :eid  :input-decoderkw
 :eoe  :output-encoderkw
 :did  :input-decoderkw
 :doe  :output-encoderkw
 :key  []
 :iv   []}
```

* **type** - A keyword that identifies the cipher you wish to use. See
[cipher.clj](cipher) for supported values.
* **mode** - A keyword that identifies the block chaining mode you wish to use.
See [modes.clj](modes) for supported values.
* **pad** - A keyword that identifies the padder you wish to use. See
[padders.clj](padders) for supported values.
* **eid** - A keyword that represents the encryption input decoder you wish to
use. See [encoders.clj](encoders) for supported values.
* **eoe** - A keyword that represents the encryption output encoder you wish to
use. See [encoders.clj](encoders) for supported values.
* **did** - A keyword that represents the decryption input decoder you wish to
use. See [encoders.clj](encoders) for supported values.
* **doe** - A keyword that represents the decryption output encoder you wish to
use. See [encoders.clj](encoders) for supported values.
* **key** - A vector of unsigned bytes (0-255) of the appropriate length that
represents the key you wish to use with the cipher.
* **iv** - A vector of unsigned bytes (0-255) of the appropriate length that
represents the IV you wish to use with the block chaining mode.
* **nonce** - A vector of unsigned bytes (0-255) of the appropriate length that
represents the nonce you with to use with the stream cipher.

### Block Cipher Usage (Quick)
```Clojure
(:require ...
          [azjure.core :refer :all]
          [azjure.cipher.aes :refer :all] ;Require the cipher(s) you wish to use
          ...
          )
```
Encrypt

```Clojure
;; Encrypt a vector of unsigned bytes
;; Note that the keys shown below are the required keys for a block cipher
(encrypt [0 0 0 0]
         {:type :aes :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [223 80 151 26 46 117 190 64 134 255 95 229 221 229 165 35]
```

Decrypt

```Clojure
;; Decrypt a vector of unsigned bytes
(decrypt [223 80 151 26 46 117 190 64 134 255 95 229 221 229 165 35]
         {:type :aes :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]
```

### Stream Cipher Usage (Quick)

```Clojure
(:require ...
          [azjure.core :refer :all]
          [azjure.cipher.salsa20 :refer :all] ;Require the ciphers(s) you wish to use
          ...
          )
```

Encrypt/Decrypt

```Clojure
;; Generate ciphertext
;; Note that the keys shown below are the required keys for a stream cipher
(encrypted-stream [0 0 0 0]
                  {:type :salsa20
                   :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                   :nonce [0 0 0 0 0 0 0 0]})
;; Should evaluate to [101 19 173 174]

;; Generate plaintext
(encrypted-stream [101 19 173 174]
                  {:type :salsa20
                   :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                   :nonce [0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]
```

See the [test directory](td) for examples

## Supported Ciphers
### Block
1. Advanced Encryption Standard (AES) - [FIPS 197](fips197)
2. Blowfish (BF) - [Blowfish Spec](blowfish)
3. CAST-256 (CAST6) - [CAST-256 RFC](cast256)
4. Twofish (TF) - [Twofish Spec](twofish)
5. TEA (TEA) - [TEA Spec](tea)
6. XTEA (XTEA) - [XTEA Spec](xtea)

### Block - In Progress
1. CAST-128 (CAST5) - [CAST-128 RFC](http://tools.ietf.org/html/rfc2144)

### Stream
1. Salsa20 (Salsa20) - [Salsa20 Spec](http://cr.yp.to/snuffle/spec.pdf)
2. ChaCha (Chacha) - [ChaCha Spec](http://cr.yp.to/chacha/chacha-20080128.pdf)

### Stream - In Progress
1. HC-128 (HC128) - [HC-128 Spec](http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf)
2. HC-256 (HC256) - [HC-256 Spec](http://www3.ntu.edu.sg/home/wuhj/research/hc/hc256_fse.pdf)
3. MICKEY2.0 (MICKEY2.0) - [MICKEY2.0 Spec](http://www.ecrypt.eu.org/stream/p3ciphers/mickey/mickey_p3.pdf)
4. Rabbit (Rabbit) - [Rabbit Spec](http://tools.ietf.org/rfc/rfc4503.txt)
5. Trivium (Trivium) - [Trivium Spec](http://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf)

## Supported Modes
Cipher modes describe the method for encrypting multiple blocks with block ciphers.

See [Mode of Operation](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) for
descriptions

### Block Only Modes
1. Electronic Codebook (ECB)
2. Cipher-Block Chaining (CBC)
3. Propagating Cipher-Block Chaining (PCBC)

### Modes able to use Block Ciphers as Stream Ciphers
1. Cipher Feedback (CFB)
2. Output Feedback (OFB)
3. Counter (CTR)

## Supported Padding
Some cipher modes (ECB, CBC, PCBC) require that the input be padded with bytes
until a multiple of the cipher's blocksize.  The following padding methods are
supported.

See [Padding](http://en.wikipedia.org/wiki/Padding_%28cryptography%29) for
descriptions

1. PKCS7
2. Zero Byte
3. ISO 10126
4. ANSI X.923
5. ISO/IEC 7816-4

## Character Encoding/Decoding
By default the API works with vectors of unsigned bytes.  However, there is
built in support for converting to and from many common character encodings.

The following encodings are supported:

1. str       - ASCII character encoding
2. hex       - hex encoding (0-9a-f)
3. base16    - Base16 encoding (0-9A-F)
4. base32    - Base32 encoding (A-Z2-7)
5. base32hex - Base32 encoding with a hex alphabet (0-9A-V)
6. base64    - Base64 encoding (A-Za-z0-9+/)
7. base64url - Base64 encoding with the URL safe alphabet (A-Za-z0-9-_)