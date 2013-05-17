(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.testmode
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.testkeys :refer :all]
            [net.ozias.crypt.testivs :refer :all]
            [net.ozias.crypt.testciphertext :refer :all]
            [net.ozias.crypt.testplaintext :refer :all]
            [net.ozias.crypt.mode.ecb :refer (->ElectronicCodebook)]
            [net.ozias.crypt.mode.cbc :refer (->CipherBlockChaining)]
            [net.ozias.crypt.mode.pcbc :refer (->PropagatingCipherBlockChaining)]
            [net.ozias.crypt.mode.cfb :refer (->CipherFeedback)]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.cipher.blockcipher :as bc]
            [net.ozias.crypt.mode.modeofoperation :as mode]))

;; #### Modes
;; Setup the mode records for use in tests
(def ECB (->ElectronicCodebook))
(def CBC (->CipherBlockChaining))
(def PCBC (->PropagatingCipherBlockChaining))
(def CFB (->CipherFeedback))

;; #### Ciphers
;; Setup the cipher records for use in tests
(def AES (->Aes))
(def BF (->Blowfish))

;; #### test-vectors
;; The mode test vectors 
(def test-vectors
  [[ECB  AES iv-128 key-128   pt-1 ecb-aes]
   [ECB  BF  iv-128 key-128   pt-1 ecb-bf]
   [CBC  AES iv-128 key-128   pt-1 cbc-aes]
   [CBC  BF  iv-128 key-128   pt-1 cbc-bf]
   [PCBC AES iv-128 key-128   pt-1 pcbc-aes]
   [PCBC BF  iv-128 key-128   pt-1 pcbc-bf]
   [CFB  AES iv-128 key-128   pt-1 cfb-aes]
   [CFB  BF  iv-128 key-128   pt-1 cfb-bf]
   [CBC  BF  iv-64  key-128-1 pt-2 cbc-bf-1]])

;; ## encrypt-blocks
;; Encrypt a vector of blocks.
(defn- encrypt-blocks [[mode cipher iv key plaintext ciphertext]]
  (is (= ciphertext (mode/encrypt-blocks mode cipher iv plaintext key))))

;; ## decrypt-blocks
;; Decrypt a vector of blocks.
(defn- decrypt-blocks [[mode cipher iv key plaintext ciphertext]]
  (is (= plaintext (mode/decrypt-blocks mode cipher iv ciphertext key))))

;; ## testModes
;; Test the blockcipher modes
(deftest testModes
  (is (= true (every? true? (map #(encrypt-blocks %) test-vectors))))
  (is (= true (every? true? (map #(decrypt-blocks %) test-vectors)))))
