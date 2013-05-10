;; # Test Blowfish Block Cipher
;; Test suite for the Blowfish block cipher.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.testblowfish
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.testkeys :refer :all]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))
;; ### bf
;; Create the Blowfish record to be used in the tests.
(def bf (->Blowfish))

;; ## encrypt-block
;; Encrypt the given block with the given key via Blowfish.
(defn- encrypt-block [block key]
  (bc/encrypt-block bf block key))

;; ## decrypt-block
;; Decrypt the given block with the given key via Blowfish.
(defn- decrypt-block [block key]
  (bc/decrypt-block bf block key))

;; ## testBlowfish
;; Test the Blowfish cipher
(deftest testBlowfish
  (testing "Blocksize"
    (is (= 64 (bc/blocksize bf)))))
