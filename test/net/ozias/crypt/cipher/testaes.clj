;; # Test AES Block Cipher
;; Test suite for the AES block cipher.
(ns ^{:author "Jason Ozias"}
     net.ozias.crypt.cipher.testaes
     (:require [clojure.test :refer :all]
               [net.ozias.crypt.cipher.aes :refer (->Aes)]
               [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### key-128
;; A sample 128-bit key as a vector of 4 32-bit words
;; as defined in Appendix C.1 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-128 [0x00010203 0x04050607 0x08090a0b 0x0c0d0e0f])

;; ### key-192
;; A sample 192-bit key as a vector of 6 32-bit words.
;; as defined in Appendix C.2 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-192 (into key-128 [0x10111213 0x14151617]))

;; ### key-256
;; A sampel 256-bit key as a vector of 8 32-bit words.
;; as defined in Appendix C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-256 (into key-192 [0x18191a1b 0x1c1d1e1f]))

;; ### pt-block
;; A sample plaintext block as a vector of 4 32-bit words
;; as defined in Appendix C.1, C.2, and C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def pt-block [0x00112233 0x44556677 0x8899aabb 0xccddeeff])

;; ### ct-128-block
;; A sample ciphertext block encrypted with the sample 128-bit key 
;; as a vector of 4 32-bit words as defined in Appendix C.1 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def ct-128-block [0x69c4e0d8 0x6a7b0430 0xd8cdb780 0x70b4c55a])

;; ### ct-192-block
;; A sample ciphertext block encrypted with the sample 192-bit key
;; as a vector of 4 32-bit words as defined in Appendix C.2 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def ct-192-block [0xdda97ca4 0x864cdfe0 0x6eaf70a0 0xec0d7191])

;; ### ct-256-block
;; A sample ciphertext block encrypted with the sample 256-bit key
;; as a vector of 4 32-bit words as defined in Appendix C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def ct-256-block [0x8ea2b7ca 0x516745bf 0xeafc4990 0x4b496089])

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

;; ## testAes
;; Test the AES cipher
(deftest testAes
  (testing "Blocksize"
    (is-eq 128 (bc/blocksize aes)))
  (testing "AES Encryption"
    (testing "128-bit Key"
      (is-eq ct-128-block (encrypt-block pt-block key-128))
      (is-neq ct-192-block (encrypt-block pt-block key-128))
      (is-neq ct-256-block (encrypt-block pt-block key-128)))
    (testing "192-bit Key"
      (is-neq ct-128-block (encrypt-block pt-block key-192))
      (is-eq ct-192-block (encrypt-block pt-block key-192))
      (is-neq ct-256-block (encrypt-block pt-block key-192)))
    (testing "256-bit Key"
      (is-neq ct-128-block (encrypt-block pt-block key-256))
      (is-neq ct-192-block (encrypt-block pt-block key-256))
      (is-eq ct-256-block (encrypt-block pt-block key-256))))
  (testing "AES Decryption"
    (testing "128-bit Key"
      (is-eq pt-block (decrypt-block ct-128-block key-128))
      (is-neq pt-block (decrypt-block ct-192-block key-128))
      (is-neq pt-block (decrypt-block ct-256-block key-128)))
    (testing "192-bit Key"
      (is-neq pt-block (decrypt-block ct-128-block key-192))
      (is-eq pt-block (decrypt-block ct-192-block key-192))
      (is-neq pt-block (decrypt-block ct-256-block key-192)))
    (testing "256-bit Key"
      (is-neq pt-block (decrypt-block ct-128-block key-256))
      (is-neq pt-block (decrypt-block ct-192-block key-256))
      (is-eq pt-block (decrypt-block ct-256-block key-256))))
  (testing "AES Encryption/Decryption"
    (testing "128-bit Key"
      (is-eq pt-block (enc-dec-block pt-block key-128 key-128))
      (is-neq pt-block (enc-dec-block pt-block key-128 key-192))
      (is-neq pt-block (enc-dec-block pt-block key-128 key-256)))
    (testing "192-bit Key"
      (is-neq pt-block (enc-dec-block pt-block key-192 key-128))
      (is-eq pt-block (enc-dec-block pt-block key-192 key-192))
      (is-neq pt-block (enc-dec-block pt-block key-192 key-256)))
    (testing "256-bit Key"
      (is-neq pt-block (enc-dec-block pt-block key-256 key-128))
      (is-neq pt-block (enc-dec-block pt-block key-256 key-192))
      (is-eq pt-block (enc-dec-block pt-block key-256 key-256)))))
