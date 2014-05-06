;; # Chacha Stream Cipher Tests

(ns org.azjure.cipher.testchacha
  "Test suite for the Chacha stream cipher"
  {:author "Jason Ozias"}
  (:require [clojure.test :refer :all]
            [org.azjure.cipher.chacha :refer [->Chacha]]
            [org.azjure.cipher.cipher :as cipher]
            [org.azjure.libtest :refer :all]
            [org.azjure.testciphertext :refer :all]
            [org.azjure.testivs :refer :all]
            [org.azjure.testkeys :refer :all]
            [org.azjure.testplaintext :refer :all]))

;; ### Record Definitions

(def ^{:doc "Chacha record to be used in the tests"} chacha (->Chacha))

;; ### Chacha Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap0
  (cipher/initialize chacha {:key zeros-128-key :nonce zeros-64-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap1
  (cipher/initialize chacha {:key zeros-256-key :nonce zeros-64-iv}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors for Chacha"} chacha-test-vectors
  [[chacha (assoc initmap0 :lower 0 :upper 64) zeros-64 chacha-128-ct]
   [chacha (assoc initmap1 :lower 0 :upper 64) zeros-64 chacha-256-ct]])


;; ### Chacha Tests

(deftest ^{:doc "Test Chacha stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor chacha-test-vectors))))
    (is (= true (every? true? (map stream-decryptor chacha-test-vectors))))))

(deftest ^{:doc "Test Chacha"} testChacha
  (testing "Chacha"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testChacha))
