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
  [[[0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
     0x0a 0xf7 0x56 0x47 0xf2 0x9f 0x61 0x5d]
    [0x0 0x0 0x0 0x0]
    [0xc842a089 0x72b43d20 0x836c91d1 0xb7530f6b]]
   [[0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
     0xbe 0xd0 0xac 0x83 0x94 0x0a 0xc2 0x98
     0xba 0xc7 0x7a 0x77 0x17 0x94 0x28 0x63]
    [0x0 0x0 0x0 0x0]
    [0x1b386c02 0x10dcadcb 0xdd0e41aa 0x08a7a7e8]]
   [[0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
     0xbe 0xd0 0xac 0x83 0x94 0x0a 0xc2 0x98
     0x8d 0x7c 0x47 0xce 0x26 0x49 0x08 0x46
     0x1c 0xc1 0xb5 0x13 0x7a 0xe6 0xb6 0x04]
    [0x0 0x0 0x0 0x0]
    [0x4f6a2038 0x286897b9 0xc9870136 0x553317fa]]
   [key-128b
    [1416127776 1903520099 1797284466 1870097952]
    [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07]] 
; 1718581280 1786080624 1931505526 1701978228 1751457900 1635416352 1685022510 67372036]
])

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
