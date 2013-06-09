;; # HC128 Stream Cipher Tests

(ns ^{:author "Jason Ozias"
      :doc "Test suite for the HC128 stream cipher"}
  org.azjure.cipher.testhc128
  (:require [clojure.test :refer :all]
            (org.azjure [libtest :refer :all]
                        [testivs :refer :all]
                        [testkeys :refer :all]
                        [testplaintext :refer :all]
                        [testciphertext :refer :all])
            (org.azjure.cipher [cipher :as cipher]
                               [streamcipher :as sc]
                               [hc128 :refer (->HC128)])))
;; ### Record Definitions

(def ^{:doc "HC-128 record to be used in the tests"} hc128 (->HC128))

;; ### HC-128 Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap0
  (cipher/initialize hc128 {:key hc-128-key :iv hc-128-iv}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap1
  (cipher/initialize hc128 {:key hc-128-key :iv hc-128-iv-1}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap2
  (cipher/initialize hc128 {:key hc-128-key-1 :iv hc-128-iv}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from the HC-128 spec"} hc128spec-test-vectors
  [[hc128 initmap0 zeros-64 hc-128-ct  ]
   [hc128 initmap1 zeros-64 hc-128-ct-1]
   [hc128 initmap2 zeros-64 hc-128-ct-2]])

;; ### HC-128 Tests

(deftest ^{:doc "Test HC-128 stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map stream-encryptor hc128spec-test-vectors))))
    (is (= true (every? true? (map stream-decryptor hc128spec-test-vectors))))))

(deftest ^{:doc "Test HC-128"} testHC128
  (testing "HC-128"
    (testStream)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testHC128))
