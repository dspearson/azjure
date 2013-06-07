;; # Salsa20 Stream Cipher Tests

(ns ^{:author "Jason Ozias"
      :doc "Test suite for the Salsa20 stream cipher"}
  net.ozias.crypt.cipher.testsalsa20
  (:require [clojure.test :refer :all]
            (net.ozias.crypt [libtest :refer :all]
                             [testivs :refer :all]
                             [testkeys :refer :all]
                             [testplaintext :refer :all]
                             [testciphertext :refer :all]
                             [cryptsuite :as cs]
                             [cryptsuite :refer (->S20CFB)]
                             [cryptsuite :refer (->S20OFB)]
                             [cryptsuite :refer (->S20CTR)])
            (net.ozias.crypt.cipher [cipher :as cipher]
                                    [streamcipher :as sc]
                                    [salsa20 :refer (->Salsa20)])))
;; ### Record Definitions

(def ^{:doc "Salsa20 record to be used in the tests"} s20 (->Salsa20))

;; The Salsa20 stream mode suites.
(def S20CFB (->S20CFB))
(def S20OFB (->S20OFB))

;; The Salsa20 counter mode suite.
(def S20CTR (->S20CTR))

;; ### Salsa20 Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap
  (cipher/initialize s20 key-128b))

;; ### Suite Test Vectors
;; Each row is
;;
;;     [suite plaintext ciphertext]
;;

(def ^{:doc "Test vectors for Salsa20 stream suites"} s20s-test-vectors
  [[S20CFB initmap phrase [0xDD 0xC8 0xD4 0xCC 0x9E 0x0D 0x46 0x37 0x14
                           0xEE 0xC4 0x9E 0xB1 0x24 0x07 0x75 0xB8 0x12
                           0xF2 0x66 0x79 0x90 0xBA 0xE6 0x30 0x26 0x83
                           0x59 0x0F 0x46 0x03 0xE8 0x4D 0x7F 0x80 0x74
                           0x23 0x0B 0x5A 0x8E 0xFB 0xA5 0x26 0xFB]]
   [S20OFB initmap phrase [0xDD 0x72 0x6A 0xDD 0x26 0x6D 0x64 0xA9 0x36
                           0xD0 0x5B 0xFE 0x01 0xE1 0x85 0xCF 0xD8 0x50
                           0x15 0xB5 0x86 0x81 0x44 0xAB 0x80 0x57 0x5B
                           0x58 0x16 0x99 0xED 0x01 0x42 0x93 0xBE 0x6C
                           0x06 0x2D 0xEF 0x11 0x51 0xC8 0xE9 0x99]]])

(def ^{:doc "Test vectors for Salsa20 counter mode suite"} s20ctr-test-vectors
  [[S20CTR initmap phrase [0x6D 0x5E 0xE6 0x3D 0x2B 0xE3 0x3D 0x3D 0x84
                           0x46 0xB1 0xBD 0xFF 0xCF 0x02 0xB2 0x9E 0x1A
                           0x57 0x2C 0x93 0x34 0x76 0x20 0x47 0xBC 0x66
                           0xE4 0x2B 0x50 0xC9 0x86 0xCF 0xFB 0x69 0x28
                           0x3A 0x1A 0x44 0x47 0xC6 0xBC 0x2C 0x64]]])

;; ### Salsa20 Tests

(deftest ^{:doc "Test Salsa20 stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map encryptor s20s-test-vectors))))
    (is (= true (every? true? (map decryptor s20s-test-vectors))))))

(deftest ^{:doc "Test Salsa20 counter mode suite"} testCounter
  (testing "Counter"
    (is (= true (every? true? (map #(encryptor % :iv iv-64b) s20ctr-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :iv iv-64b) s20ctr-test-vectors))))))

(deftest ^{:doc "Test Salsa20"} testSalsa20
  (testing "Salsa20"
    (testStream)
    (testCounter)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testSalsa20))
