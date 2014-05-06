;; # Grain128 Stream Cipher Tests

(ns org.azjure.cipher.testgrain128
  "Test suite for the Grain128 stream cipher"
  {:author "Jason Ozias"}
  (:require [clojure.test :refer :all]
            [org.azjure.cipher.cipher :as cipher]
            [org.azjure.cipher.grain128 :refer [->Grain128]]
            [org.azjure.libtest :refer :all]
            [org.azjure.testciphertext :refer :all]
            [org.azjure.testivs :refer :all]
            [org.azjure.testkeys :refer :all]
            [org.azjure.testplaintext :refer :all]))

;; ### Record Definitions

(def ^{:doc "Grain128 record to be used in the tests"} grain128 (->Grain128))

;; ### Grain128 Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap0
  (cipher/initialize grain128 {:key zeros-128-key :iv zeros-96-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap1
  (cipher/initialize grain128 {:key grain-128-key :iv grain-96-iv}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from the HC-256 spec"} grain128spec-test-vectors
  [[grain128 (assoc initmap0 :lower 0 :upper 16) zeros grain-128-ct-0]
   [grain128 (assoc initmap1 :lower 0 :upper 16) zeros grain-128-ct-1]])

;; ### Grain128 Tests

(deftest ^{:doc "Test Grain128 stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor grain128spec-test-vectors))))
    (is (= true (every? true? (map stream-decryptor grain128spec-test-vectors))))))

(deftest ^{:doc "Test Grain128"} testGrain128
  (testing "Grain128"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testGrain128))
