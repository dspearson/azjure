;; ## Test Crypt Suites
;; Test the crypt suites (e.g. AES/CBC/PKCS7)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testcryptsuite
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.libbyte :refer (last-byte)]
            [net.ozias.crypt.cryptsuite :as cs]
            [net.ozias.crypt.cryptsuite :refer (->AESECBPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->AESECBZERO)]
            [net.ozias.crypt.cryptsuite :refer (->AESECBISO10126)]
            [net.ozias.crypt.cryptsuite :refer (->AESECBX923)]
            [net.ozias.crypt.cryptsuite :refer (->AESCBCPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->AESCBCZERO)]
            [net.ozias.crypt.cryptsuite :refer (->AESCBCISO10126)]
            [net.ozias.crypt.cryptsuite :refer (->AESCBCX923)]
            [net.ozias.crypt.cryptsuite :refer (->BFECBPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->BFECBZERO)]
            [net.ozias.crypt.cryptsuite :refer (->BFECBISO10126)]
            [net.ozias.crypt.cryptsuite :refer (->BFECBX923)]
            [net.ozias.crypt.cryptsuite :refer (->BFCBCPKCS7)]
            [net.ozias.crypt.cryptsuite :refer (->BFCBCZERO)]
            [net.ozias.crypt.cryptsuite :refer (->BFCBCISO10126)]
            [net.ozias.crypt.cryptsuite :refer (->BFCBCX923)]
            [net.ozias.crypt.testivs :refer (iv-128)]
            [net.ozias.crypt.testkeys :refer (key-128)]))

;; #### AESECBPKCS7
;; #### AESECBZERO
;; #### AESECBISO10126
;; #### AESECBX923
;; #### AESCBCPKCS7
;; #### AESCBCZERO
;; #### AESCBCISO10126
;; #### AESCBCX923
;; Setup the AES suites for use in testing.
(def AESECBPKCS7 (->AESECBPKCS7))
(def AESECBZERO (->AESECBZERO))
(def AESECBISO10126 (->AESECBISO10126))
(def AESECBX923 (->AESECBX923))
(def AESCBCPKCS7 (->AESCBCPKCS7))
(def AESCBCZERO (->AESCBCZERO))
(def AESCBCISO10126 (->AESCBCISO10126))
(def AESCBCX923 (->AESCBCX923))

;; #### BFECBPKCS7
;; #### BFECBZERO
;; #### BFECBISO10126
;; #### BFECBX923
;; #### BFCBCPKCS7
;; #### BFCBCZERO
;; #### BFCBCISO10126
;; #### BFCBCX923
;; Setup the Blowfish suites for use in testing.
(def BFECBPKCS7 (->BFECBPKCS7))
(def BFECBZERO (->BFECBZERO))
(def BFECBISO10126 (->BFECBISO10126))
(def BFECBX923 (->BFECBX923))
(def BFCBCPKCS7 (->BFCBCPKCS7))
(def BFCBCZERO (->BFCBCZERO))
(def BFCBCISO10126 (->BFCBCISO10126))
(def BFCBCX923 (->BFCBCX923))

;; #### name-bytes
;; My name as a byte array of UTF-8 bytes
(def name-bytes (.getBytes "Jason Ozias" "UTF-8"))

;; #### aes-X-X-res
;; The expected result of encrypting name-bytes
;; with the AES cipher with various modes and paddings.
(def aes-ecb-pkcs7-res [0x9e94c4e4 0x1336d233 0xdff541da 0xf087c9a7])
(def aes-ecb-zero-res [0x007aabf0 0x7a9b9c1d 0x5d222885 0xd4b51dcc])
(def aes-ecb-x923-res [0x4609ef72 0xcec01435 0x711663f8 0x1aa876ec])
(def aes-cbc-pkcs7-res [0x184a08c1 0x04d97f63 0xd1692da5 0x01193b83])
(def aes-cbc-zero-res [0x9d02ac5f 0xef9aae8d 0x4170955d 0xb8a83e91])
(def aes-cbc-x923-res [0x52c34aae 0x9e4d5953 0xd0f05a65 0xafbc56e2])

;; #### bf-X-X-res
;; The expected result of encrypting name-bytes
;; with the Blowfish cipher and various modes and padding.
(def bf-ecb-pkcs7-res [0x615b80bf 0xd8d093b3 0x8db20d6d 0xd1ef46c3])
(def bf-ecb-zero-res [0x615b80bf 0xd8d093b3 0x70aa0c4d 0x9abf4d20])
(def bf-ecb-x923-res [0x615b80bf 0xd8d093b3 0xc517e502 0xbbb74029])
(def bf-cbc-pkcs7-res [0x47b754e6 0xddeaff3f 0x37af8d49 0xf5e0e239])
(def bf-cbc-zero-res [0x47b754e6 0xddeaff3f 0x6928b01d 0x842403d9])
(def bf-cbc-x923-res [0x47b754e6 0xddeaff3f 0x16c11f09 0xa23a4d3d])

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
               (String. (cs/decrypt AESECBZERO key-128 iv-128 aes-ecb-zero-res)))))
      (testing "ISO10126"
        (let [aes-ecb-iso10126-res (cs/encrypt AESECBISO10126 key-128 iv-128 name-bytes)]
          (is (= 4 (count aes-ecb-iso10126-res)))
          (is (= "Jason Ozias"
                 (String. (cs/decrypt AESECBISO10126 key-128 iv-128 aes-ecb-iso10126-res))))))
      (testing "X.923"
        (is (= aes-ecb-x923-res
               (cs/encrypt AESECBX923 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt AESECBX923 key-128 iv-128 aes-ecb-x923-res))))))
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
               (String. (cs/decrypt AESCBCZERO key-128 iv-128 aes-cbc-zero-res)))))
      (testing "ISO10126"
        (let [aes-cbc-iso10126-res (cs/encrypt AESCBCISO10126 key-128 iv-128 name-bytes)]
          (is (= 4 (count aes-cbc-iso10126-res)))
          (is (= "Jason Ozias"
                 (String. (cs/decrypt AESCBCISO10126 key-128 iv-128 aes-cbc-iso10126-res))))))
      (testing "X.923"
        (is (= aes-cbc-x923-res
               (cs/encrypt AESCBCX923 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt AESCBCX923 key-128 iv-128 aes-cbc-x923-res)))))))
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
               (String. (cs/decrypt BFECBZERO key-128 iv-128 bf-ecb-zero-res)))))
      (testing "ISO10126"
        (let [bf-ecb-iso10126-res (cs/encrypt BFECBISO10126 key-128 iv-128 name-bytes)]
          (is (= 4 (count bf-ecb-iso10126-res)))
          (is (= "Jason Ozias"
                 (String. (cs/decrypt BFECBISO10126 key-128 iv-128 bf-ecb-iso10126-res))))))
      (testing "X.923"
        (is (= bf-ecb-x923-res
               (cs/encrypt BFECBX923 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt BFECBX923 key-128 iv-128 bf-ecb-x923-res))))))
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
               (String. (cs/decrypt BFCBCZERO key-128 iv-128 bf-cbc-zero-res)))))
      (testing "ISO10126"
        (let [bf-cbc-iso10126-res (cs/encrypt BFCBCISO10126 key-128 iv-128 name-bytes)]
          (is (= 4 (count bf-cbc-iso10126-res)))
          (is (= "Jason Ozias"
                 (String. (cs/decrypt BFCBCISO10126 key-128 iv-128 bf-cbc-iso10126-res))))))
      (testing "X.923"
        (is (= bf-cbc-x923-res
               (cs/encrypt BFCBCX923 key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (cs/decrypt BFCBCX923 key-128 iv-128 bf-cbc-x923-res))))))))
