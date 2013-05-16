;; ## Test Cipher Suites
;; Test the cipher suites (e.g. AES/CBC/PKCS7)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testcipher
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.cryptsuite :as cs]
            [net.ozias.crypt.cryptsuite :refer (->AESECBPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->BFECBPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->AESCBCPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->BFCBCPKCS7)]
            [net.ozias.crypt.testivs :refer (iv-128)]
            [net.ozias.crypt.testkeys :refer (key-128)]))

;; #### AESECBPKCS7
;; Setup the AES/ECB/PKCS7 suite for use in testing.
(def AESECBPKCS7 (->AESECBPKCS7))
;; #### BFECBPKCS7
;; Setup the Blowfish/ECB/PKCS7 suite for use in testing.
(def BFECBPKCS7 (->BFECBPKCS7))
;; #### AESCBCPKCS7
;; Setup the AES/CBC/PKCS7 suite for use in testing.
(def AESCBCPKCS7 (->AESCBCPKCS7))
;; #### BFCBCPKCS7
;; Setup the Blowfish/CBC/PKCS7 suite for use in testing.
(def BFCBCPKCS7 (->BFCBCPKCS7))

;; #### name-bytes
;; My name as a byte array of UTF-8 bytes
(def name-bytes (.getBytes "Jason Ozias" "UTF-8"))

;; #### aes-ecb-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the AES/ECB/PKCS7 suite.
(def aes-ecb-pkcs7-res [0x9e94c4e4 0x1336d233 0xdff541da 0xf087c9a7])

;; #### aes-cbc-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the AES/CBC/PKCS7 suite.
(def aes-cbc-pkcs7-res [0x184a08c1 0x04d97f63 0xd1692da5 0x01193b83])

;; #### bf-ecb-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the Blowfish/ECB/PKCS7 suite.
(def bf-ecb-pkcs7-res [0x615b80bf 0xd8d093b3 0x8db20d6d 0xd1ef46c3])

;; #### bf-cbc-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the Blowfish/CBC/PKCS7 suite.
(def bf-cbc-pkcs7-res [0x47b754e6 0xddeaff3f 0x37af8d49 0xf5e0e239])

;; ### testSuites
;; Test the various cipher suites.
(deftest testSuites
  (testing "ECB"
    (testing "PKCS7"
      (testing "AES"
        (is (= aes-ecb-pkcs7-res
               (cs/encrypt AESECBPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt AESECBPKCS7 key-128 iv-128 aes-ecb-pkcs7-res)))))
      (testing "Blowfish"
        (is (= bf-ecb-pkcs7-res
               (cs/encrypt BFECBPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt BFECBPKCS7 key-128 iv-128 bf-ecb-pkcs7-res)))))))
  (testing "CBC"
    (testing "PKCS7"
      (testing "AES"
        (is (= aes-cbc-pkcs7-res 
               (cs/encrypt AESCBCPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias" 
               (String. (cs/decrypt AESCBCPKCS7 key-128 iv-128 aes-cbc-pkcs7-res) "UTF-8"))))
      (testing "Blowfish"
        (is (= bf-cbc-pkcs7-res
               (cs/encrypt BFCBCPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt BFCBCPKCS7 key-128 iv-128 bf-cbc-pkcs7-res))))))))
