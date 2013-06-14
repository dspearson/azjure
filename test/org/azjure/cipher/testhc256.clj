;; # HC256 Stream Cipher Tests

(ns ^{:author "Jason Ozias"
      :doc "Test suite for the HC256 stream cipher"}
  org.azjure.cipher.testhc256
  (:require [clojure.test :refer :all]
            (org.azjure [libtest :refer :all]
                        [testivs :refer :all]
                        [testkeys :refer :all]
                        [testplaintext :refer :all]
                        [testciphertext :refer :all])
            (org.azjure.cipher [cipher :as cipher]
                               [streamcipher :as sc]
                               [hc256 :refer (->HC256)])))
;; ### Record Definitions

(def ^{:doc "HC256 record to be used in the tests"} hc256 (->HC256))

;; ### HC-256 Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap0
  (cipher/initialize hc256 {:key zeros-256-key :iv zeros-256-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap1
  (cipher/initialize hc256 {:key zeros-256-key :iv hc-256-256-iv-1}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap2
  (cipher/initialize hc256 {:key hc-256-256-key-1 :iv zeros-256-iv}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from the HC-256 spec"} hc256spec-test-vectors
  [[hc256 (assoc initmap0 :lower 0 :upper 64) zeros-64 hc-256-ct-0]
   [hc256 (assoc initmap1 :lower 0 :upper 64) zeros-64 hc-256-ct-1]
   [hc256 (assoc initmap2 :lower 0 :upper 64) zeros-64 hc-256-ct-2]])

;; ### HC-256 Tests

(deftest ^{:doc "Test HC-256 stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor hc256spec-test-vectors))))
    (is (= true (every? true? (map stream-decryptor hc256spec-test-vectors))))))

(deftest ^{:doc "Test HC-256"} testHC256
  (testing "HC-256"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testHC256))
