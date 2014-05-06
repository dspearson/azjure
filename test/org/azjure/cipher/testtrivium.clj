;;  ## Trivium Stream Cipher Tests

(ns org.azjure.cipher.testtrivium
  "Test suite for the Trivium stream cipher"
  {:author "Jason Ozias"}
  (:require [clojure.test :refer :all]
            [org.azjure.cipher.cipher :as cipher]
            [org.azjure.cipher.trivium :refer [->Trivium]]
            [org.azjure.libtest :refer :all]
            [org.azjure.testciphertext :refer :all]
            [org.azjure.testivs :refer :all]
            [org.azjure.testkeys :refer :all]
            [org.azjure.testplaintext :refer :all]))
;; ### Record Definitions

(def ^{:doc "Trivium record to be used in the tests"}
  trivium (->Trivium))

;; ### Trivium Initialization

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap0
  (cipher/initialize trivium {:key trivium-80-key-0 :iv zeros-80-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap1
  (cipher/initialize trivium {:key zeros-80-key :iv trivium-80-iv}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from Trivium spec"}
  triviumspec-test-vectors
  [[trivium (assoc initmap0 :lower 0   :upper 64 ) zeros-64 trivium-80-ct-0]
   [trivium (assoc initmap0 :lower 192 :upper 256) zeros-64 trivium-80-ct-1]
   [trivium (assoc initmap0 :lower 256 :upper 320) zeros-64 trivium-80-ct-2]
   [trivium (assoc initmap0 :lower 448 :upper 512) zeros-64 trivium-80-ct-3]
   [trivium (assoc initmap1 :lower 0   :upper 64 ) zeros-64 trivium-80-ct-4]
   [trivium (assoc initmap1 :lower 192 :upper 256) zeros-64 trivium-80-ct-5]
   [trivium (assoc initmap1 :lower 256 :upper 320) zeros-64 trivium-80-ct-6]
   [trivium (assoc initmap1 :lower 448 :upper 512) zeros-64 trivium-80-ct-7]])

;; ### Trivium Tests

(deftest ^{:doc "Test Trivium stream suites"}
  testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor triviumspec-test-vectors))))
    (is (= true (every? true? (map stream-decryptor triviumspec-test-vectors))))))

(deftest ^{:doc "Test Trivium"}
  testTrivium
  (testing "Trivium"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"}
  test-ns-hook []
  (testTrivium))
