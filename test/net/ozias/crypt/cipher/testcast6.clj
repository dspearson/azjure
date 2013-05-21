;; ## Test CAST6 Block Cipher
;; Test suite for the CAST6 block cipher.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.testcast6
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.testkeys :refer :all]
            [net.ozias.crypt.cipher.cast6 :refer (->CAST6)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; #### c6
;; Create the CAST6 record to be used in the tests.
(def c6 (->CAST6))

;; #### test-vectors
;; Test vectors found at
;; [http://tools.ietf.org/html/rfc2612#page-10](http://tools.ietf.org/html/rfc2612#page-10)
;;
;; Each row represents
;;
;;     [  key  ] [plaintext] [ciphertext]
;;     [kw1-kw8] [ptw1 ptw2] [ctw1  ctw2]
;;
;; as vectors of 32-bit words.
(def test-vectors
  [[[0x2342bb9e 0xfa38542c 0x0af75647 0xf29f615d]
    [0x0 0x0 0x0 0x0]
    [0xc842a089 0x72b43d20 0x836c91d1 0xb7530f6b]]
   [[0x2342bb9e 0xfa38542c 0xbed0ac83 0x940ac298 0xbac77a77 0x17942863]
    [0x0 0x0 0x0 0x0]
    [0x1b386c02 0x10dcadcb 0xdd0e41aa 0x08a7a7e8]]
   [[0x2342bb9e 0xfa38542c 0xbed0ac83 0x940ac298 0x8d7c47ce 0x26490846 0x1cc1b513 0x7ae6b604]
    [0x0 0x0 0x0 0x0]
    [0x4f6a2038 0x286897b9 0xc9870136 0x553317fa]]])

;; ## test-encrypt
;; Helper function for CAST5 encryption testing
(defn- test-encrypt [[key cleartext ciphertext]]
  (is (= ciphertext (bc/encrypt-block c6 cleartext key))))

;; ## test-decrypt
;; Helper function for CAST5 decryption testing
(defn- test-decrypt [[key cleartext ciphertext]]
  (is (= cleartext (bc/decrypt-block c6 ciphertext key))))

;; ## testCAST6
;; Test the CAST6 cipher
(deftest testCAST6
  (testing "Blocksize"
    (is (= 128 (bc/blocksize c6))))
  (testing "Encryption"
    (is (= true (every? true? (map #(test-encrypt %) test-vectors)))))
  (testing "Decryption"
    (is (= true (every? true? (map #(test-decrypt %) test-vectors))))))
