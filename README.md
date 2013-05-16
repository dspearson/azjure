azjure
======

Cryptography implementations in Clojure

## Usage

## Supported Block Ciphers
1. Advanced Encryption Standard (AES) - [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
2. Blowfish (BF) - [Blowfish Spec](https://www.schneier.com/paper-blowfish-fse.html)

## Supported Modes
Blocks cipher modes describe the method for encrypting multiple blocks.

See [Mode of Operation](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) for
descriptions

1. Electronic Codebook (ECB)
2. Cipher-Block Chaining (CBC)

## Padding
Some block cipher modes require that the input be padding with bytes until a multiple of
the cipher's blocksize.  The following padding methods are supported.

See [Padding](http://en.wikipedia.org/wiki/Padding_%28cryptography%29) for descriptions

1. Zero Byte
2. ANSI X.923
3. ISO 10126
4. PKCS7
5. ISO/IEC 7816-4
