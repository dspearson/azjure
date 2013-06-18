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

;; ### Specification Test Vectors
;; Each row is
;;
;;     [cipher initmap plaintext ciphertext]
;;

(def ^{:doc "Test vectors from the XTEA spec"} xteaspec-test-vectors
  [[XTEA initmap0 zeros-64-pt xtea-128-ct-0]
   [XTEA initmap0 tea-64-pt-0 xtea-128-ct-1]
   [XTEA initmap1 zeros-64-pt xtea-128-ct-2]
   [XTEA initmap1 tea-64-pt-0 xtea-128-ct-3]])

