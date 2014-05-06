;; # Mickey2 Stream Cipher Tests

(ns org.azjure.cipher.testmickey2
  "Test suite for the Mickey2 stream cipher"
  {:author "Jason Ozias"}
  (:require [clojure.test :refer :all]
            [org.azjure.cipher.cipher :as cipher]
            [org.azjure.cipher.mickey2 :refer [->Mickey2]]
            [org.azjure.libtest :refer :all]
            [org.azjure.testciphertext :refer :all]
            [org.azjure.testivs :refer :all]
            [org.azjure.testkeys :refer :all]
            [org.azjure.testplaintext :refer :all]))

;; ### Record Definitions

(def ^{:doc "Mickey2 record to be used in the tests"} mickey2 (->Mickey2))

;; ### Mickey2 Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap0
  (cipher/initialize mickey2 {:key mickey2-80-key-0 :iv zeros-32-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap1
  (cipher/initialize mickey2 {:key mickey2-80-key-1 :iv zeros-32-iv}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from the MICKEY2 spec"} mickey2spec-test-vectors
  [[mickey2 (assoc initmap0 :lower 0 :upper 512) zeros-512 mickey2-80-ct-0]
   [mickey2 (assoc initmap1 :lower 0 :upper 512) zeros-512 mickey2-80-ct-1]])

;; ### Mickey2 Tests

(deftest ^{:doc "Test Mickey2 stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor mickey2spec-test-vectors))))
    (is (= true (every? true? (map stream-decryptor mickey2spec-test-vectors))))))

(deftest ^{:doc "Test Mickey2"} testMickey2
  (testing "Mickey2"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testMickey2))
