;; ## Test Cipher Suites
;; Test the cipher suites (e.g. AES/CBC/PKCS7)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testcipher
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.cipher.blockcipher :as bc]
            [net.ozias.crypt.mode.modeofoperation :as mode]
            [net.ozias.crypt.padding.pad :as padder]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.mode.cbc :refer (->CipherBlockChaining)]
            [net.ozias.crypt.mode.ecb :refer (->ElectronicCodebook)]
            [net.ozias.crypt.padding.pkcs7pad :refer (->PKCS7pad)]
            [net.ozias.crypt.testivs :refer (iv-128)]
            [net.ozias.crypt.testkeys :refer (key-128)]))

;; #### PKCS7
;; Setup the padding records for use in testing
(def PKCS7 (->PKCS7pad))

;; #### AES, Blowfish
;; Setup the ciphers for use in testing
(def AES (->Aes))
(def Blowfish (->Blowfish))

;; #### ECB,CBC
;; Setup the mode for use in testing
(def ECB (->ElectronicCodebook))
(def CBC (->CipherBlockChaining))

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

;; ### encrypt
;; Helper function for encryption
(defn- encrypt [[cipher mode padding] key iv bytearr]
  (mode/encrypt-blocks mode cipher iv (padder/pad padding bytearr cipher) key))

;; ### decrypt
;; Helper function for decryption
(defn- decrypt [[cipher mode padding] key iv words]
  (padder/unpad padding (mode/decrypt-blocks mode cipher iv words key) cipher))

;; ### testSuites
;; Test the various cipher suites.
(deftest testSuites
  (testing "ECB"
    (testing "PKCS7"
      (testing "AES"
        (is (= aes-ecb-pkcs7-res
               (encrypt [AES ECB PKCS7] key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (decrypt [AES ECB PKCS7] key-128 iv-128 aes-ecb-pkcs7-res)))))
      (testing "Blowfish"
        (is (= bf-ecb-pkcs7-res
               (encrypt [Blowfish ECB PKCS7] key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (decrypt [Blowfish ECB PKCS7] key-128 iv-128 bf-ecb-pkcs7-res)))))))
  (testing "CBC"
    (testing "PKCS7"
      (testing "AES"
        (is (= aes-cbc-pkcs7-res 
               (encrypt [AES CBC PKCS7] key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias" 
               (String. (decrypt [AES CBC PKCS7] key-128 iv-128 aes-cbc-pkcs7-res) "UTF-8"))))
      (testing "Blowfish"
        (is (= bf-cbc-pkcs7-res
               (encrypt [Blowfish CBC PKCS7] key-128 iv-128 name-bytes)))
        (is (= "Jason Ozias"
               (String. (decrypt [Blowfish CBC PKCS7] key-128 iv-128 bf-cbc-pkcs7-res))))))))
