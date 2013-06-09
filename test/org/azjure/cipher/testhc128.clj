;; # HC128 Stream Cipher Tests

(ns ^{:author "Jason Ozias"
      :doc "Test suite for the HC128 stream cipher"}
  org.azjure.cipher.testhc128
  (:require [clojure.test :refer :all]
            (org.azjure [libtest :refer :all]
                        [testivs :refer :all]
                        [testkeys :refer :all]
                        [testplaintext :refer :all]
                        [testciphertext :refer :all]
                        [cryptsuite :as cs]
                        [cryptsuite :refer (->HC128CFB)]
                        [cryptsuite :refer (->HC128OFB)]
                        [cryptsuite :refer (->HC128CTR)])
            (org.azjure.cipher [cipher :as cipher]
                               [streamcipher :as sc]
                               [hc128 :refer (->HC128)])))
;; ### Record Definitions

(def ^{:doc "HC-128 record to be used in the tests"} hc128 (->HC128))

;; The HC-128 stream mode suites.
(def HC128CFB (->HC128CFB))
(def HC128OFB (->HC128OFB))

;; The HC-128 counter mode suite.
(def HC128CTR (->HC128CTR))

;; ### HC-128 Initialization

;(def ^{:doc "Initialization map to be used in the suite tests."} initmap
;  (cipher/initialize hc128 key-128b))

(def initmap)

;; ### Suite Test Vectors
;; Each row is
;;
;;     [suite plaintext ciphertext]
;;

(def ^{:doc "Test vectors for HC-128 stream suites"} hc128s-test-vectors
  [;[HC128CFB initmap phrase []]
   ;[HC128OFB initmap phrase []]
])

(def ^{:doc "Test vectors for HC-128 counter mode suite"} hc128ctr-test-vectors
  [;[HC128CTR initmap phrase []]
])

;; ### HC-128 Tests

(deftest ^{:doc "Test HC-128 stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map encryptor hc128s-test-vectors))))
    (is (= true (every? true? (map decryptor hc128s-test-vectors))))))

(deftest ^{:doc "Test HC-128 counter mode suite"} testCounter
  (testing "Counter"
    (is (= true (every? true? (map #(encryptor % :iv iv-64b) hc128ctr-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :iv iv-64b) hc128ctr-test-vectors))))))

(deftest ^{:doc "Test HC-128"} testHC128
  (testing "HC-128"
    (testStream)
    (testCounter)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testHC128))
