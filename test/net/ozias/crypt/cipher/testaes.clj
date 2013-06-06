;; # Test AES Block Cipher
;; Test suite for the AES block cipher.
(ns ^{:author "Jason Ozias"}
     net.ozias.crypt.cipher.testaes
     (:require [clojure.test :refer :all]
               [net.ozias.crypt.testkeys :refer :all]
               [net.ozias.crypt.cipher.aes :refer (->Aes)]
               [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### pt-block
;; A sample plaintext block as a vector of 16 bytes
;; as defined in Appendix C.1, C.2, and C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def pt-block [0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77
               0x88 0x99 0xaa 0xbb 0xcc 0xdd 0xee 0xff])

;; ### ct-128-block
;; A sample ciphertext block encrypted with the sample 128-bit key 
;; as a vector of 16 bytes as defined in Appendix C.1 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def ct-128-block [0x69 0xc4 0xe0 0xd8 0x6a 0x7b 0x04 0x30
                   0xd8 0xcd 0xb7 0x80 0x70 0xb4 0xc5 0x5a])

;; ### ct-192-block
;; A sample ciphertext block encrypted with the sample 192-bit key
;; as a vector of 4 32-bit words as defined in Appendix C.2 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def ct-192-block [0xdd 0xa9 0x7c 0xa4 0x86 0x4c 0xdf 0xe0
                   0x6e 0xaf 0x70 0xa0 0xec 0x0d 0x71 0x91])

;; ### ct-256-block
;; A sample ciphertext block encrypted with the sample 256-bit key
;; as a vector of 4 32-bit words as defined in Appendix C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def ct-256-block [0x8e 0xa2 0xb7 0xca 0x51 0x67 0x45 0xbf
                   0xea 0xfc 0x49 0x90 0x4b 0x49 0x60 0x89])

;; ### aes
;; Create the Aes record to be used in the tests.
(def aes (->Aes))

;; ## encrypt-block
;; Encrypt the given block with the given key via AES.
(defn- encrypt-block [block key]
  (bc/encrypt-block aes block key))

;; ## decrypt-block
;; Decrypt the given block with the given key via AES.
(defn- decrypt-block [block key]
  (bc/decrypt-block aes block key))

;; ## enc-decrypt-block
;; Encrypt the given block with enckey, 
;; then decrypt the output of the encrypt with the deckey.
(defn- enc-dec-block [block enckey deckey]
  (decrypt-block (encrypt-block block enckey) deckey))

;; ## is-eq
;; is equal
;;
;; Evaluates to
;;
;;     (is (= expected test))
;;
(defn is-eq [expected test]
  (is (= expected test)))

;; ## is-neq
;; is not equal
;;
;; Evaluates to
;;
;;     (is (not (= expected test)))
;; 
(defn is-neq [expected test]
  (is (not (= expected test))))

;; ## testAES
;; Test the AES cipher
(deftest testAES
  (testing "Blocksize"
    (is-eq 128 (bc/blocksize aes)))
  (testing "AES Encryption"
    (testing "128-bit Key"
      (is-eq ct-128-block (encrypt-block pt-block key-128b1))
      (is-neq ct-192-block (encrypt-block pt-block key-128b1))
      (is-neq ct-256-block (encrypt-block pt-block key-128b1)))
    (testing "192-bit Key"
      (is-neq ct-128-block (encrypt-block pt-block key-192b))
      (is-eq ct-192-block (encrypt-block pt-block key-192b))
      (is-neq ct-256-block (encrypt-block pt-block key-192b)))
    (testing "256-bit Key"
      (is-neq ct-128-block (encrypt-block pt-block key-256b))
      (is-neq ct-192-block (encrypt-block pt-block key-256b))
      (is-eq ct-256-block (encrypt-block pt-block key-256b))))
  (testing "AES Decryption"
    (testing "128-bit Key"
      (is-eq pt-block (decrypt-block ct-128-block key-128b1))
      (is-neq pt-block (decrypt-block ct-192-block key-128b1))
      (is-neq pt-block (decrypt-block ct-256-block key-128b1)))
    (testing "192-bit Key"
      (is-neq pt-block (decrypt-block ct-128-block key-192b))
      (is-eq pt-block (decrypt-block ct-192-block key-192b))
      (is-neq pt-block (decrypt-block ct-256-block key-192b)))
    (testing "256-bit Key"
      (is-neq pt-block (decrypt-block ct-128-block key-256b))
      (is-neq pt-block (decrypt-block ct-192-block key-256b))
      (is-eq pt-block (decrypt-block ct-256-block key-256b))))
  (testing "AES Encryption/Decryption"
    (testing "128-bit Key"
      (is-eq pt-block (enc-dec-block pt-block key-128b1 key-128b1))
      (is-neq pt-block (enc-dec-block pt-block key-128b1 key-192b))
      (is-neq pt-block (enc-dec-block pt-block key-128b1 key-256b)))
    (testing "192-bit Key"
      (is-neq pt-block (enc-dec-block pt-block key-192b key-128b1))
      (is-eq pt-block (enc-dec-block pt-block key-192b key-192b))
      (is-neq pt-block (enc-dec-block pt-block key-192b key-256b)))
    (testing "256-bit Key"
      (is-neq pt-block (enc-dec-block pt-block key-256b key-128b1))
      (is-neq pt-block (enc-dec-block pt-block key-256b key-192b))
      (is-eq pt-block (enc-dec-block pt-block key-256b key-256b)))))
