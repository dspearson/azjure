;; # Test AES Encryption Engine
(ns ^{:author "Jason Ozias"}
     net.ozias.crypt.cipher.testaes
     (:require [clojure.test :refer :all]
               [net.ozias.crypt.cipher.aes :refer (->Aes)]
               [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### key-128
;; A 128-bit test key as a vector of 4 32-bit words
;; as defined in Appendix C.1 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-128 
  (vector 0x00010203
          0x04050607
          0x08090a0b
          0x0c0d0e0f))

;; ### key-192
;; A 192-bit test key as a vector of 6 32-bit words.
;; as defined in Appendix C.2 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-192 
  (vector 0x00010203
          0x04050607
          0x08090a0b
          0x0c0d0e0f
          0x10111213
          0x14151617))

;; ### key-256
;; A 256-bit test key as a vector of 8 32-bit words.
;; as defined in Appendix C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-256 
  (vector 0x00010203
          0x04050607
          0x08090a0b
          0x0c0d0e0f
          0x10111213
          0x14151617
          0x18191a1b
          0x1c1d1e1f))

;; ### block
;; Test plaintext block as a vector of 4 32-bit words
;; as defined in Appendix C.1, C.2, and C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def block
  (vector 0x00112233
          0x44556677
          0x8899aabb
          0xccddeeff))

;; ## e128-block
;; Test block encrypted with 128-bit key as a vector of 4 32-bit words
;; as defined in Appendix C.1 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def e128-block
  (vector 0x69c4e0d8
          0x6a7b0430 
          0xd8cdb780
          0x70b4c55a))

;; ## e192-block
;; Test block encrypted with 192-bit key as a vector of 4 32-bit words
;; as defined in Appendix C.2 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def e192-block
  (vector 0xdda97ca4
          0x864cdfe0
          0x6eaf70a0
          0xec0d7191))

;; ## e256-block
;; Test block encrypted with 256-bit key as a vector of 4 32-bit words
;; as defined in Appendix C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def e256-block
  (vector 0x8ea2b7ca
          0x516745bf
          0xeafc4990 
          0x4b496089))

;; ## aes
;; Create the Aes record to be used in the tests.
(def aes (->Aes))

;; ## encrypt-block
;; Encrypt the given block with the given key with AES.
(defn encrypt-block [block key]
  (bc/encrypt-block aes block key))

;; ## decrypt-block
;; Decrypt the given block with the given key with AES.
(defn decrypt-block [block key]
  (bc/decrypt-block aes block key))

;; ## testAes
;; Test the AES cipher.
(deftest testAes
  (testing "Blocksize"
    (is (= 128 (bc/blocksize aes))))
  (testing "AES Encryption"
    (testing "128-bit Key"
      (is (= e128-block (encrypt-block block key-128)))
      (is (not (= e192-block (encrypt-block block key-128))))
      (is (not (= e256-block (encrypt-block block key-128)))))
    (testing "192-bit Key"
      (is (not (= e128-block (encrypt-block block key-192))))      
      (is (= e192-block (encrypt-block block key-192)))
      (is (not (= e256-block (encrypt-block block key-192)))))
    (testing "256-bit Key"
      (is (not (= e128-block (encrypt-block block key-256))))
      (is (not (= e192-block (encrypt-block block key-256))))
      (is (= e256-block (encrypt-block block key-256)))))
  (testing "AES Decryption"
    (testing "128-bit Key"
      (is (= block (decrypt-block e128-block key-128)))
      (is (not (= block (decrypt-block e192-block key-128))))
      (is (not (= block (decrypt-block e256-block key-128)))))
    (testing "192-bit Key"
      (is (not (= block (decrypt-block e128-block key-192))))
      (is (= block (decrypt-block e192-block key-192)))
      (is (not (= block (decrypt-block e256-block key-192)))))
    (testing "256-bit Key"
      (is (not (= block (decrypt-block e128-block key-256))))
      (is (not (= block (decrypt-block e192-block key-256))))
      (is (= block (decrypt-block e256-block key-256)))))
  (testing "AES Encryption/Decryption"
    (is (= block (decrypt-block (encrypt-block block key-128) key-128)))
    (is (= block (decrypt-block (encrypt-block block key-192) key-192)))
    (is (= block (decrypt-block (encrypt-block block key-256) key-256)))))
