azjure
======

Cryptography implementations in Clojure

## Usage
Add the following in the dependencies section of your project.clj file

```Clojure
:dependencies [...
               [net.ozias.crypt/azjure "0.1.0"]
               ...]
```

Require the CryptSuite protocol

```Clojure
(:require [net.ozias.crypt.cryptsuite :as cs])
```

Then require the suite you wish to use (a suite is a combination of cipher, mode, and padding method)

```Clojure
(:require [net.ozias.crypt.cryptsuite :refer (->AESECBPKCS7)]
```

Encrypt

```Clojure
;; Initialize the record to use
(def AESCBCPKCS7 (->AESCBCPKCS7))
;; Encrypt
(cs/encrypt AESCBCPKCS7 key iv bytearr)
```

Decrypt

```Clojure
;; Initialize the record to use
(def AESCBCPKCS7 (->AESCBCPKCS7))
;; Decrypt
(cs/decrypt AESCBCPKCS7 key iv words)
```

See [testcryptsuite.clj](https://github.com/CraZySacX/azjure/blob/master/test/net/ozias/crypt/testcryptsuite.clj) for examples

## Supported Block Ciphers
1. Advanced Encryption Standard (AES) - [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
2. Blowfish (BF) - [Blowfish Spec](https://www.schneier.com/paper-blowfish-fse.html)
3. CAST-128 (CAST5) - [CAST-128 RFC](http://tools.ietf.org/html/rfc2144)
4. CAST-256 (CAST6) - [CAST-256 RFC](http://tools.ietf.org/html/rfc2612)

## Supported Modes
Blocks cipher modes describe the method for encrypting multiple blocks.

See [Mode of Operation](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) for
descriptions

1. Electronic Codebook (ECB)
2. Cipher-Block Chaining (CBC)
3. Propagating Cipher-Block Chaining (PCBC)
4. Cipher Feedback (CFB)
5. Output Feedback (OFB)

## Supported Padding
Some block cipher modes require that the input be padded with bytes until a multiple of
the cipher's blocksize.  The following padding methods are supported.

See [Padding](http://en.wikipedia.org/wiki/Padding_%28cryptography%29) for descriptions

1. PKCS7
2. Zero Byte
3. ISO 10126
4. ANSI X.923
5. ISO/IEC 7816-4

## In Progress
* Camellia
* Twofish Cipher
* CTR Mode