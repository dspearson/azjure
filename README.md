azjure
======

Encryption in Clojure

## Version
[![Clojars Project](http://clojars.org/azjure/latest-version.svg)](http://clojars.org/azjure)

## Status
[![Build Status](https://travis-ci.org/CraZySacX/azjure.svg?branch=master)](https://travis-ci.org/CraZySacX/azjure)

## Usage
Add the following in the dependencies section of your project.clj file

```Clojure
:dependencies [...
               [azjure "1.0.0-SNAPSHOT"]
               ...]
```

### Block Ciphers
```Clojure
(:require (azjure [core :refer :all]
                  [encoders :refer :all]
                  [padders :refer :all])
          (azjure.cipher [aes :refer :all]
                         [blockcipher :refer :all]))
```
Encrypt

```Clojure
;; Initialize the cipher (key should be a vector of unsigned bytes).
(encrypt [0 0 0 0] {:type :aes :mode :ecb :pad zero
                    :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                    :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
```

Decrypt

```Clojure
;; Initialize the cipher (key should be a vector of unsigned bytes).
(def initmap (cipher/initialize (->AES) {:key key}))
;; Decrypt (ciphertext and iv should be vectors of unsigned bytes)
(cs/decrypt (->AESCBCPKCS7) ciphertext iv initmap)
```

### Stream Ciphers

```Clojure
(:require (org.azjure.cipher [cipher :as cipher]
                             [streamcipher :as sc]
                             [salsa20 :refer (->Salsa20]))
```

Encrypt

```Clojure
;; Initialize the record to use
(def s20 (->Salsa20))
;; Initialize the cipher.  Note the map argument usually takes a map of the
;; format {:key key :iv iv}.  In Salsa20's case it is {:key key :nonce nonce}.
;; This will evaluate to a map to use during keystream generation
(def initmap (cipher/initialize s20 {:key key :nonce nonce}))
;; Generate keystream and encrypt
(mapv bit-xor plaintext (sc/generate-keystream s20 initmap [0 (count plaintext)]))
```

Decrypt

```Clojure
;; Initialize the record to use
(def s20 (->Salsa20))
;; Initialize the cipher.  Note the map argument usually takes a map of the
;; format {:key key :iv iv}.  In Salsa20's case it is {:key key :nonce nonce}.
;; This will evaluate to a map to use during keystream generation
(def initmap (cipher/initialize s20 {:key key :nonce nonce}))
;; Generate keystream and encrypt
(mapv bit-xor ciphertext (sc/generate-keystream s20 initmap [0 (count ciphertext)]))
```

See the [test directory](https://github.com/CraZySacX/azjure/tree/master/test/org/azjure/cipher) for examples

## Supported Ciphers
### Block
1. Advanced Encryption Standard (AES) - [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
2. Blowfish (BF) - [Blowfish Spec](https://www.schneier.com/paper-blowfish-fse.html)
3. CAST-128 (CAST5) - [CAST-128 RFC](http://tools.ietf.org/html/rfc2144)
4. CAST-256 (CAST6) - [CAST-256 RFC](http://tools.ietf.org/html/rfc2612)
5. Twofish (TF) - [Twofish Spec](http://www.schneier.com/paper-twofish-paper.pdf)
6. TEA (TEA) - [TEA Spec](http://citeseer.ist.psu.edu/viewdoc/download?doi=10.1.1.45.281&rep=rep1&type=pdf)
7. XTEA (XTEA) - [XTEA Spec](http://www.cix.co.uk/~klockstone/xtea.pdf)

### Stream
1. Salsa20 (Salsa20) - [Salsa20 Spec](http://cr.yp.to/snuffle/spec.pdf)
2. ChaCha (Chacha) - [ChaCha Spec](http://cr.yp.to/chacha/chacha-20080128.pdf)
3. HC-128 (HC128) - [HC-128 Spec](http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf)
4. HC-256 (HC256) - [HC-256 Spec](http://www3.ntu.edu.sg/home/wuhj/research/hc/hc256_fse.pdf)
5. MICKEY2.0 (MICKEY2.0) - [MICKEY2.0 Spec](http://www.ecrypt.eu.org/stream/p3ciphers/mickey/mickey_p3.pdf)
6. Rabbit (Rabbit) - [Rabbit Spec](http://tools.ietf.org/rfc/rfc4503.txt)
7. Trivium (Trivium) - [Trivium Spec](http://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf)

## Supported Modes
Cipher modes describe the method for encrypting multiple blocks with block ciphers.

See [Mode of Operation](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) for
descriptions

### Block Modes
1. Electronic Codebook (ECB)
2. Cipher-Block Chaining (CBC)
3. Propagating Cipher-Block Chaining (PCBC)

### Stream Modes with Block Ciphers
1. Cipher Feedback (CFB)
2. Output Feedback (OFB)
3. Counter (CTR)

## Supported Padding
Some cipher modes (ECB, CBC, PCBC) require that the input be padded with bytes until a 
multiple of the cipher's blocksize.  The following padding methods are supported.

See [Padding](http://en.wikipedia.org/wiki/Padding_%28cryptography%29) for descriptions

1. PKCS7
2. Zero Byte
3. ISO 10126
4. ANSI X.923
5. ISO/IEC 7816-4
