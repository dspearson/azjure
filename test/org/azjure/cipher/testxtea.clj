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

;; ### Suite Test Vectors
;; Each row is
;;
;;     [suite initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors for XTEA block suites"} xteablock-test-vectors
  [[XTEAECBPKCS7    initmap0 phrase [0x36 0xFD 0x7B 0x16 0xB9 0x3E 0xFB 0xA7
                                     0x39 0x1F 0xC5 0x69 0x3E 0xCA 0xC4 0x56
                                     0xB3 0xE1 0x57 0xD2 0xAA 0xBD 0x2B 0xFA
                                     0xFB 0x3F 0xA4 0x40 0xAB 0x2A 0x73 0x58
                                     0x6E 0xB7 0x3C 0xE4 0x19 0x61 0xCB 0xE5
                                     0xBC 0xB9 0x20 0x5E 0x0D 0x66 0x5F 0xC9]]
   [XTEAECBZERO     initmap0 phrase [0x36 0xFD 0x7B 0x16 0xB9 0x3E 0xFB 0xA7
                                     0x39 0x1F 0xC5 0x69 0x3E 0xCA 0xC4 0x56
                                     0xB3 0xE1 0x57 0xD2 0xAA 0xBD 0x2B 0xFA
                                     0xFB 0x3F 0xA4 0x40 0xAB 0x2A 0x73 0x58
                                     0x6E 0xB7 0x3C 0xE4 0x19 0x61 0xCB 0xE5
                                     0x91 0x46 0xD2 0x75 0xA5 0x61 0x56 0xCE]]
   [XTEAECBX923     initmap0 phrase [0x36 0xFD 0x7B 0x16 0xB9 0x3E 0xFB 0xA7
                                     0x39 0x1F 0xC5 0x69 0x3E 0xCA 0xC4 0x56
                                     0xB3 0xE1 0x57 0xD2 0xAA 0xBD 0x2B 0xFA
                                     0xFB 0x3F 0xA4 0x40 0xAB 0x2A 0x73 0x58
                                     0x6E 0xB7 0x3C 0xE4 0x19 0x61 0xCB 0xE5
                                     0x01 0xDD 0xB3 0x38 0xE8 0x2A 0x03 0xD1]]
   [XTEAECBISO7816  initmap0 phrase [0x36 0xFD 0x7B 0x16 0xB9 0x3E 0xFB 0xA7
                                     0x39 0x1F 0xC5 0x69 0x3E 0xCA 0xC4 0x56
                                     0xB3 0xE1 0x57 0xD2 0xAA 0xBD 0x2B 0xFA
                                     0xFB 0x3F 0xA4 0x40 0xAB 0x2A 0x73 0x58
                                     0x6E 0xB7 0x3C 0xE4 0x19 0x61 0xCB 0xE5
                                     0x94 0xCD 0x5D 0x35 0xA7 0x1A 0x5D 0xA2]]
   [XTEACBCPKCS7    initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0x1C 0xC2 0x13 0x8F 0xC0 0xC3 0x42 0x7C
                                     0x2A 0x1B 0x82 0x17 0xD8 0xF1 0xF6 0xF7
                                     0x31 0xA0 0x20 0xBA 0x41 0xD7 0x29 0xEB
                                     0x29 0x73 0x4E 0xC0 0xF8 0x87 0xF3 0xBF
                                     0x71 0x26 0xB4 0x58 0xE5 0x14 0xFB 0x15]]
   [XTEACBCZERO     initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0x1C 0xC2 0x13 0x8F 0xC0 0xC3 0x42 0x7C
                                     0x2A 0x1B 0x82 0x17 0xD8 0xF1 0xF6 0xF7
                                     0x31 0xA0 0x20 0xBA 0x41 0xD7 0x29 0xEB
                                     0x29 0x73 0x4E 0xC0 0xF8 0x87 0xF3 0xBF
                                     0xDA 0x13 0x42 0x85 0xC3 0xFE 0xDD 0x58]]
   [XTEACBCX923     initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0x1C 0xC2 0x13 0x8F 0xC0 0xC3 0x42 0x7C
                                     0x2A 0x1B 0x82 0x17 0xD8 0xF1 0xF6 0xF7
                                     0x31 0xA0 0x20 0xBA 0x41 0xD7 0x29 0xEB
                                     0x29 0x73 0x4E 0xC0 0xF8 0x87 0xF3 0xBF
                                     0xD0 0xD8 0x51 0x94 0x1D 0x92 0x2B 0x9D]]
   [XTEACBCISO7816  initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0x1C 0xC2 0x13 0x8F 0xC0 0xC3 0x42 0x7C
                                     0x2A 0x1B 0x82 0x17 0xD8 0xF1 0xF6 0xF7
                                     0x31 0xA0 0x20 0xBA 0x41 0xD7 0x29 0xEB
                                     0x29 0x73 0x4E 0xC0 0xF8 0x87 0xF3 0xBF
                                     0x7B 0xBB 0x52 0xF6 0xB5 0x61 0x16 0xF2]]
   [XTEAPCBCPKCS7   initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0xBF 0x64 0x0D 0x7B 0x2C 0xD7 0xED 0x5E
                                     0x47 0x28 0xEE 0x95 0x84 0xCD 0x70 0xE7
                                     0x7B 0xD7 0x1C 0x5B 0x6E 0xA0 0x56 0xBA
                                     0xFF 0x06 0xB3 0x3A 0xDD 0x68 0x9C 0xA4
                                     0xA2 0xD6 0xBF 0xD6 0xDE 0xC6 0xCB 0xFE]]
   [XTEAPCBCZERO    initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0xBF 0x64 0x0D 0x7B 0x2C 0xD7 0xED 0x5E
                                     0x47 0x28 0xEE 0x95 0x84 0xCD 0x70 0xE7
                                     0x7B 0xD7 0x1C 0x5B 0x6E 0xA0 0x56 0xBA
                                     0xFF 0x06 0xB3 0x3A 0xDD 0x68 0x9C 0xA4
                                     0x7B 0x04 0x7A 0x1C 0x91 0xFB 0x92 0x99]]
   [XTEAPCBCX923    initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0xBF 0x64 0x0D 0x7B 0x2C 0xD7 0xED 0x5E
                                     0x47 0x28 0xEE 0x95 0x84 0xCD 0x70 0xE7
                                     0x7B 0xD7 0x1C 0x5B 0x6E 0xA0 0x56 0xBA
                                     0xFF 0x06 0xB3 0x3A 0xDD 0x68 0x9C 0xA4
                                     0x67 0x8C 0x8D 0x98 0xFB 0xC3 0x32 0xED]]
   [XTEAPCBCISO7816 initmap0 phrase [0x41 0x90 0x74 0xDC 0x30 0x96 0xE4 0xE8
                                     0xBF 0x64 0x0D 0x7B 0x2C 0xD7 0xED 0x5E
                                     0x47 0x28 0xEE 0x95 0x84 0xCD 0x70 0xE7
                                     0x7B 0xD7 0x1C 0x5B 0x6E 0xA0 0x56 0xBA
                                     0xFF 0x06 0xB3 0x3A 0xDD 0x68 0x9C 0xA4
                                     0xB9 0x62 0xBA 0x50 0x29 0x36 0x61 0x06]]])

(def ^{:doc "Test vectors for XTEA stream suites"}
  xteas-test-vectors
  [[XTEACFB initmap0 phrase [0xF1 0x57 0xF2 0x79 0x74 0x9F 0xBD 0x67
                             0xB8 0xDF 0x1F 0x3C 0x8F 0x9D 0xD2 0xCB
                             0x68 0x76 0xC8 0x9B 0xEC 0x8B 0x9E 0x37
                             0x02 0xEF 0x42 0x8F 0x9C 0xBE 0xBB 0xA9
                             0x5D 0x29 0x75 0xA8 0xE6 0x6C 0x8D 0x05
                             0xC5 0x65 0x22 0x17]]
   [XTEAOFB initmap0 phrase [0xF1 0xC4 0x9F 0x64 0xC2 0x8F 0x77 0xA7
                             0x9B 0xBA 0xF7 0x60 0xDD 0xB6 0x25 0x81
                             0x55 0xBE 0xC4 0x10 0xFD 0xD7 0x07 0x84
                             0x84 0x6E 0x98 0xDF 0x1E 0xD8 0xFE 0x81
                             0xEF 0x71 0xF0 0x6D 0xA2 0x8D 0x4D 0x4B
                             0xEE 0xB7 0xFD 0x02]]])

(def ^{:doc "Test vectors for XTEA counter mode suite"}
  xteactr-test-vectors
  [[XTEACTR initmap0 phrase [0x0E 0xFE 0x4A 0x2A 0xF9 0xAB 0x3A 0xDF
                             0x31 0xB6 0x4D 0x78 0xE7 0xA9 0x3D 0x9C
                             0x3C 0xF9 0x57 0x2A 0xE2 0xAB 0x3E 0xCC
                             0x29 0xB6 0x40 0x7C 0xED 0xAC 0x73 0xC8
                             0x32 0xF3 0x0F 0x66 0xE9 0xA4 0x2A 0x9C
                             0x3E 0xF9 0x48 0x24]]])

;; ### XTEA Tests

(deftest ^{:doc "Test XTEA spec test vectors"} testSpec
  (testing "Spec"
    (is (= true (every? true? (map encrypt-block xteaspec-test-vectors))))
    (is (= true (every? true? (map decrypt-block xteaspec-test-vectors))))))

(deftest ^{:doc "Test XTEA block suites"} testBlock
  (testing "Block"
    (is (= true (every? true? (map encryptor xteablock-test-vectors))))
    (is (= true (every? true? (map decryptor xteablock-test-vectors))))))

(deftest ^{:doc "Test XTEA stream suites"} testStream
  (testing "Stream"
    (is (= true (every? true? (map #(encryptor % :iv iv-64b) xteas-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :iv iv-64b) xteas-test-vectors))))))

(deftest ^{:doc "Test XTEA counter mode suite"} testCounter
  (testing "Counter"
    (is (= true (every? true? (map #(encryptor % :iv iv-32b) xteactr-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :iv iv-32b) xteactr-test-vectors))))))

(deftest ^{:doc "Test XTEA"} testXTEA
  (testing "XTEA"
    (testSpec)
    (testBlock)
    (testStream)
    (testCounter)))

(defn ^{:doc "Namespace hook to run tests in proper order"} test-ns-hook
  []
  (testXTEA))