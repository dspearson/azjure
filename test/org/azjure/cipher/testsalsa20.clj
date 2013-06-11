;; # Salsa20 Stream Cipher Tests
(ns ^{:author "Jason Ozias"
      :doc "Test suite for the Salsa20 stream cipher"}
  org.azjure.cipher.testsalsa20
  (:require [clojure.test :refer :all]
            (org.azjure [libtest :refer :all]
                        [testivs :refer :all]
                        [testkeys :refer :all]
                        [testplaintext :refer :all]
                        [testciphertext :refer :all])
            (org.azjure.cipher [cipher :as cipher]
                               [streamcipher :as sc]
                               [salsa20 :refer (->Salsa20)])))
;; ### Record Definitions

(def ^{:doc "Salsa20 record to be used in the tests"} s20 (->Salsa20))

;; ### Salsa20 Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap0
 (cipher/initialize s20 {:key zeros-128-key :nonce zeros-64-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap1
 (cipher/initialize s20 {:key zeros-256-key :nonce zeros-64-iv}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors for Salsa20"} s20-test-vectors
  [[s20 initmap0 zeros-64 s20-128-ct]
   [s20 initmap1 zeros-64 s20-256-ct]])


;; ### Salsa20 Tests

(deftest ^{:doc "Test Salsa20 stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor s20-test-vectors))))
    (is (= true (every? true? (map stream-decryptor s20-test-vectors))))))

(deftest ^{:doc "Test Salsa20"} testSalsa20
  (testing "Salsa20"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testSalsa20))
