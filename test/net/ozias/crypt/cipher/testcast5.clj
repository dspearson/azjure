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
;;     [kw1 kw2] [ptw1 ptw2] [ctw1  ctw2]
;;
;; as vectors of 32-bit words.
(def test-vectors
  [[[0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78 0x23 0x45 0x67 0x89 0x34 0x56 0x78 0x9A]
    [0x01234567 0x89ABCDEF]
    [0x238B4FE5 0x847E44B2]]
   [[0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78 0x23 0x45]
    [0x01234567 0x89ABCDEF]
    [0xEB6A711A 0x2C02271B]]
   [[0x01 0x23 0x45 0x67 0x12]
    [0x01234567 0x89ABCDEF]
    [0x7AC816D1 0x6E9B302E]]])

;; ## test-encrypt
;; Helper function for CAST5 encryption testing
(defn- test-encrypt [[key cleartext ciphertext]]
  (is (= ciphertext (bc/encrypt-block c5 cleartext key))))

;; ## test-decrypt
;; Helper function for CAST5 decryption testing
(defn- test-decrypt [[key cleartext ciphertext]]
  (is (= cleartext (bc/decrypt-block c5 ciphertext key))))

;; ## testCAST5
;; Test the CAST5 cipher
(deftest testCAST5
  (testing "Blocksize"
    (is (= 64 (bc/blocksize c5))))
  (testing "Encryption"
    (is (= true (every? true? (map #(test-encrypt %) test-vectors)))))
  (testing "Decryption"
    (is (= true (every? true? (map #(test-decrypt %) test-vectors))))))
