;; ## Test Crypt Suites
;; Test the crypt suites (e.g. AES/CBC/PKCS7)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testcryptsuite
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.cryptsuite :as cs]
            [net.ozias.crypt.cryptsuite :refer (->AESECBPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->AESECBZERO)]
            [net.ozias.crypt.cryptsuite :refer (->AESCBCPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->AESCBCZERO)]
            [net.ozias.crypt.cryptsuite :refer (->BFECBPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->BFECBZERO)]
            [net.ozias.crypt.cryptsuite :refer (->BFCBCPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->BFCBCZERO)]
            [net.ozias.crypt.testivs :refer (iv-128)]
            [net.ozias.crypt.testkeys :refer (key-128)]))

;; #### AESECBPKCS7
;; #### AESECBZERO
;; #### AESCBCPKCS7
;; #### AESCBCZERO
;; Setup the AES suites for use in testing.
(def AESECBPKCS7 (->AESECBPKCS7))
(def AESCBCPKCS7 (->AESCBCPKCS7))
(def AESECBZERO (->AESECBZERO))
(def AESCBCZERO (->AESCBCZERO))

;; #### BFECBPKCS7
;; #### BFECBZERO
;; #### BFCBCPKCS7
;; #### BFCBCZERO
;; Setup the Blowfish suites for use in testing.
(def BFECBPKCS7 (->BFECBPKCS7))
(def BFCBCPKCS7 (->BFCBCPKCS7))
(def BFECBZERO (->BFECBZERO))
(def BFCBCZERO (->BFCBCZERO))

;; #### name-bytes
;; My name as a byte array of UTF-8 bytes
(def name-bytes (.getBytes "Jason Ozias" "UTF-8"))

;; #### aes-ecb-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the AES/ECB/PKCS7 suite.
(def aes-ecb-pkcs7-res [0x9e94c4e4 0x1336d233 0xdff541da 0xf087c9a7])

;; #### aes-ecb-zero-res
;; The expected result of encrypting name-bytes
;; with the AES/ECB/Zeropad suite.
(def aes-ecb-zero-res [0x007aabf0 0x7a9b9c1d 0x5d222885 0xd4b51dcc])

;; #### aes-cbc-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the AES/CBC/PKCS7 suite.
(def aes-cbc-pkcs7-res [0x184a08c1 0x04d97f63 0xd1692da5 0x01193b83])

;; #### aes-cbc-zero-res
;; The expected result of encrypting name-bytes
;; with the AES/CBC/Zeropad suite.
(def aes-cbc-zero-res [0x9d02ac5f 0xef9aae8d 0x4170955d 0xb8a83e91])

;; #### bf-ecb-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the Blowfish/ECB/PKCS7 suite.
(def bf-ecb-pkcs7-res [0x615b80bf 0xd8d093b3 0x8db20d6d 0xd1ef46c3])
(def bf-ecb-zero-res [0x615b80bf 0xd8d093b3 0x70aa0c4d 0x9abf4d20])

;; #### bf-cbc-pkcs7-res
;; The expected result of encrypting name-bytes
;; with the Blowfish/CBC/PKCS7 suite.
(def bf-cbc-pkcs7-res [0x47b754e6 0xddeaff3f 0x37af8d49 0xf5e0e239])
(def bf-cbc-zero-res [0x47b754e6 0xddeaff3f 0x6928b01d 0x842403d9])

;; ### testSuites
;; Test the various cipher suites.
(deftest testSuites
  (testing "AES"
    (testing "ECB"
      (testing "PKCS7"
        (is (= aes-ecb-pkcs7-res
               (cs/encrypt AESECBPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt AESECBPKCS7 key-128 iv-128 aes-ecb-pkcs7-res)))))
      (testing "Zeropad"
        (is (= aes-ecb-zero-res
               (cs/encrypt AESECBZERO key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt AESECBZERO key-128 iv-128 aes-ecb-zero-res))))))
    (testing "CBC"
      (testing "PKCS7"
        (is (= aes-cbc-pkcs7-res 
               (cs/encrypt AESCBCPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias" 
               (String. (cs/decrypt AESCBCPKCS7 key-128 iv-128 aes-cbc-pkcs7-res) "UTF-8"))))
      (testing "Zeropad"
        (is (= aes-cbc-zero-res
               (cs/encrypt AESCBCZERO key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt AESCBCZERO key-128 iv-128 aes-cbc-zero-res)))))))
  (testing "Blowfish"
    (testing "ECB"
      (testing "PKCS7"
        (is (= bf-ecb-pkcs7-res
               (cs/encrypt BFECBPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt BFECBPKCS7 key-128 iv-128 bf-ecb-pkcs7-res)))))
      (testing "Zeropad"
        (is (= bf-ecb-zero-res
               (cs/encrypt BFECBZERO key-128 iv-128 name-bytes)))

        (is (= "Jason Ozias"
               (String. (cs/decrypt BFECBZERO key-128 iv-128 bf-ecb-zero-res))))))
    (testing "CBC"
      (testing "PKCS7"
        (is (= bf-cbc-pkcs7-res
               (cs/encrypt BFCBCPKCS7 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt BFCBCPKCS7 key-128 iv-128 bf-cbc-pkcs7-res)))))
      (testing "Zeropad"
        (is (= bf-cbc-zero-res
               (cs/encrypt BFCBCZERO key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt BFCBCZERO key-128 iv-128 bf-cbc-zero-res))))))))
