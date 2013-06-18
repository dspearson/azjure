;; # XTEA Block Cipher Tests
(ns ^{:author "Jason Ozias"
      :doc "Test suite for the XTEA block cipher"}
  org.azjure.cipher.testxtea
  (:require [clojure.test :refer :all]
            (org.azjure [libtest :refer :all]
                        [testivs :refer :all]
                        [testkeys :refer :all]
                        [testplaintext :refer :all]
                        [testciphertext :refer :all]
                        [cryptsuite :as cs]
                        [cryptsuite :refer (->XTEAECBPKCS7)]
                        [cryptsuite :refer (->XTEAECBZERO)]
                        [cryptsuite :refer (->XTEAECBISO10126)]
                        [cryptsuite :refer (->XTEAECBX923)]
                        [cryptsuite :refer (->XTEAECBISO7816)]
                        [cryptsuite :refer (->XTEACBCPKCS7)]
                        [cryptsuite :refer (->XTEACBCZERO)]
                        [cryptsuite :refer (->XTEACBCISO10126)]
                        [cryptsuite :refer (->XTEACBCX923)]
                        [cryptsuite :refer (->XTEACBCISO7816)]
                        [cryptsuite :refer (->XTEAPCBCPKCS7)]
                        [cryptsuite :refer (->XTEAPCBCZERO)]
                        [cryptsuite :refer (->XTEAPCBCISO10126)]
                        [cryptsuite :refer (->XTEAPCBCX923)]
                        [cryptsuite :refer (->XTEAPCBCISO7816)]
                        [cryptsuite :refer (->XTEACFB)]
                        [cryptsuite :refer (->XTEAOFB)]
                        [cryptsuite :refer (->XTEACTR)])
            (org.azjure.cipher [cipher :as cipher]
                               [blockcipher :as bc]
                               [xtea :refer (->XTEA)])))

;; ### Record Definitions

(def ^{:doc "XTEA record to be used in the tests"} XTEA (->XTEA))

;; The XTEA block mode suites.
(def XTEAECBPKCS7 (->XTEAECBPKCS7))
(def XTEAECBZERO (->XTEAECBZERO))
(def XTEAECBISO10126 (->XTEAECBISO10126))
(def XTEAECBX923 (->XTEAECBX923))
(def XTEAECBISO7816 (->XTEAECBISO7816))
(def XTEACBCPKCS7 (->XTEACBCPKCS7))
(def XTEACBCZERO (->XTEACBCZERO))
(def XTEACBCISO10126 (->XTEACBCISO10126))
(def XTEACBCX923 (->XTEACBCX923))
(def XTEACBCISO7816 (->XTEACBCISO7816))
(def XTEAPCBCPKCS7 (->XTEAPCBCPKCS7))
(def XTEAPCBCZERO (->XTEAPCBCZERO))
(def XTEAPCBCISO10126 (->XTEAPCBCISO10126))
(def XTEAPCBCX923 (->XTEAPCBCX923))
(def XTEAPCBCISO7816 (->XTEAPCBCISO7816))

;; The XTEA stream mode suites.
(def XTEACFB (->XTEACFB))
(def XTEAOFB (->XTEAOFB))

;; The XTEA counter mode suite.
(def XTEACTR (->XTEACTR))

;; ### XTEA Initialization

(def ^{:doc "Initialization map to be used in the suite tests."} initmap0
  (cipher/initialize XTEA {:key zeros-128-key}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap1
  (cipher/initialize XTEA {:key xtea-128-key-0}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap2
  (cipher/initialize XTEA {:key xtea-128-key-1}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap3
  (cipher/initialize XTEA {:key xtea-128-key-2}))

(def ^{:doc "Initialization map to be used in the suite tests."} initmap4
  (cipher/initialize XTEA {:key xtea-128-key-3}))

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from the XTEA spec"} xteaspec-test-vectors
  [[XTEA initmap0 zeros-64-pt  xtea-128-ct-0]
   [XTEA initmap0 xtea-64-pt-0 xtea-128-ct-1]
   [XTEA initmap1 zeros-64-pt  xtea-128-ct-2]
   [XTEA initmap1 xtea-64-pt-0 xtea-128-ct-3]
   [XTEA initmap2 xtea-64-pt-1 xtea-128-ct-4]
   [XTEA initmap3 xtea-64-pt-2 xtea-128-ct-5]
   [XTEA initmap4 xtea-64-pt-3 xtea-128-ct-6]
   [XTEA initmap4 zeros-64-pt  xtea-128-ct-7]
   [XTEA initmap0 xtea-64-pt-3 xtea-128-ct-8]
   [XTEA initmap0 xtea-64-pt-4 xtea-128-ct-9]])

;; ### XTEA Tests

(deftest ^{:doc "Test XTEA spec test vectors"} testSpec
  (testing "Spec"
    (is (= true (every? true? (map encrypt-block xteaspec-test-vectors))))
    (is (= true (every? true? (map decrypt-block xteaspec-test-vectors))))))

;(deftest ^{:doc "Test XTEA block suites"} testBlock
;  (testing "Block"
;    (is (= true (every? true? (map encryptor xteablock-test-vectors))))
;    (is (= true (every? true? (map decryptor xteablock-test-vectors))))))

;(deftest ^{:doc "Test XTEA stream suites"} testStream
;  (testing "Stream"
;    (is (= true (every? true? (map encryptor xteas-test-vectors))))
;    (is (= true (every? true? (map decryptor xteas-test-vectors))))))

;(deftest ^{:doc "Test XTEA counter mode suite"} testCounter
;  (testing "Counter"
;    (is (= true (every? true? (map #(encryptor % :iv iv-64b) xteactr-test-vectors))))
;    (is (= true (every? true? (map #(decryptor % :iv iv-64b) xteactr-test-vectors))))))

(deftest ^{:doc "Test XTEA"} testXTEA
  (testing "XTEA"
    (testSpec)
    ;(testBlock)
    ;(testStream)
    ;(testCounter)
))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testXTEA))
