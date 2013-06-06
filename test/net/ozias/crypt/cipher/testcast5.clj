;; ## Test CAST5 Block Cipher
;; Test suite for the CAST5 block cipher.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.testcast5
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.testkeys :refer :all]
            [net.ozias.crypt.cipher.cast5 :refer (->CAST5)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; #### c5
;; Create the CAST5 record to be used in the tests.
(def c5 (->CAST5))

;; #### test-vectors
;; Test vectors found at
;; [http://tools.ietf.org/html/rfc2144#appendix-B.1](http://tools.ietf.org/html/rfc2144#appendix-B.1)
;;
;; Each row represents
;;
;;     [  key  ] [plaintext] [ciphertext]
;;
;; as vectors of bytes.
(def test-vectors
  [[[0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78 0x23 0x45 0x67 0x89 0x34 0x56 0x78 0x9A]
    [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
    [0x23 0x8B 0x4F 0xE5 0x84 0x7E 0x44 0xB2]]
   [[0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78 0x23 0x45]
    [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
    [0xEB 0x6A 0x71 0x1A 0x2C 0x02 0x27 0x1B]]
   [[0x01 0x23 0x45 0x67 0x12]
    [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
    [0x7A 0xC8 0x16 0xD1 0x6E 0x9B 0x30 0x2E]]])

;; ## test-encrypt
;; Helper function for CAST5 encryption testing
(defn- test-encrypt [[key plaintext ciphertext]]
  (is (= ciphertext (bc/encrypt-block c5 plaintext key))))

;; ## test-decrypt
;; Helper function for CAST5 decryption testing
(defn- test-decrypt [[key plaintext ciphertext]]
  (is (= plaintext (bc/decrypt-block c5 ciphertext key))))

;; ## testCAST5
;; Test the CAST5 cipher
(deftest testCAST5
  (testing "Blocksize"
    (is (= 64 (bc/blocksize c5))))
  (testing "Encryption"
    (is (= true (every? true? (map test-encrypt test-vectors)))))
  (testing "Decryption"
    (is (= true (every? true? (map test-decrypt test-vectors))))))
