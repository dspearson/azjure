;; # Rabbit Stream Cipher Tests

(ns org.azjure.cipher.testrabbit
  "Test suite for the Rabbit stream cipher"
  {:author "Jason Ozias"}
  (:require [clojure.test :refer :all]
            [org.azjure.cipher.cipher :as cipher]
            [org.azjure.cipher.rabbit :refer [->Rabbit]]
            [org.azjure.libtest :refer :all]
            [org.azjure.testciphertext :refer :all]
            [org.azjure.testivs :refer :all]
            [org.azjure.testkeys :refer :all]
            [org.azjure.testplaintext :refer :all]))
;; ### Record Definitions

(def ^{:doc "Rabbit record to be used in the tests"}
  rabbit (->Rabbit))

;; ### Rabbit Initialization

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap0
  (cipher/initialize rabbit {:key zeros-128-key}))

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap1
  (cipher/initialize rabbit {:key rabbit-128-key-0}))

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap2
  (cipher/initialize rabbit {:key rabbit-128-key-1}))

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap3
  (cipher/initialize rabbit {:key zeros-128-key :iv zeros-64-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap4
  (cipher/initialize rabbit {:key zeros-128-key :iv rabbit-64-iv-0}))

(def ^{:doc "Initialization map to be used in the suite tests."}
  initmap5
  (cipher/initialize rabbit {:key zeros-128-key :iv rabbit-64-iv-1}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from Rabbit spec"}
  rabbitspec-test-vectors
  [[rabbit (assoc initmap0 :lower 0 :upper 48) zeros-48 rabbit-128-ct-0]
   [rabbit (assoc initmap1 :lower 0 :upper 48) zeros-48 rabbit-128-ct-1]
   [rabbit (assoc initmap2 :lower 0 :upper 48) zeros-48 rabbit-128-ct-2]
   [rabbit (assoc initmap3 :lower 0 :upper 48) zeros-48 rabbit-128-ct-3]
   [rabbit (assoc initmap4 :lower 0 :upper 48) zeros-48 rabbit-128-ct-4]
   [rabbit (assoc initmap5 :lower 0 :upper 48) zeros-48 rabbit-128-ct-5]])

;; ### Rabbit Tests

(deftest ^{:doc "Test Rabbit stream suites"}
  testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor rabbitspec-test-vectors))))
    (is (= true (every? true? (map stream-decryptor rabbitspec-test-vectors))))))

(deftest ^{:doc "Test Rabbit"}
  testRabbit
  (testing "Rabbit"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"}
  test-ns-hook []
  (testRabbit))
