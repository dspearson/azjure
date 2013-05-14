;; # Test PKCS7pad Padding
;; Test suite for PKCS7 padding
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.testpkcs7pad
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.cipher.twofish :refer (->Twofish)]
            [net.ozias.crypt.padding.pkcs7pad :refer (->PKCS7pad)]
            [net.ozias.crypt.padding.pad :as padder]))

;; ### PKCS7pad
;; Setup the PKCS7pad record for usage in tests
(def PKCS7pad (->PKCS7pad))
;; ### Aes
;; Setup the Aes record for usage in tests
(def Aes (->Aes))
;; ### Blowfish
;; Setup the Blowfish record for usage in tests
(def Blowfish (->Blowfish))
;; ### Twofish
;; Setup the Twofish record for usage in tests
(def Twofish (->Twofish))

;; ### test-bytes
;; A sample byte array of length two, initialize to
;;
;;     [0x01 0x02]
;;
(def test-bytes (byte-array 2 [(byte 0x01) (byte 0x02)]))
;; ### name-bytes
;; A sample byte array generated from the UTF-8 bytes of my
;; name
(def name-bytes (.getBytes "Jason Ozias" "UTF-8"))

;; ### res-64
;; The expected result of padding the test-bytes array
;; to the proper size for a 64-bit blocksize cipher
(def res-64 [0x01020606 0x06060606])
;; ### res-128
;; The expected result of padding the test-bytes array
;; to the proper size for a 128-bit blocksize cipher
(def res-128 [0x01020e0e 0x0e0e0e0e 0x0e0e0e0e 0x0e0e0e0e])
;; ### res-name
;; The expected result of padding the name-bytes array
;; to the proper size for a 64-bit or 128-bit blocksize cipher
(def res-name [0x4a61736f 0x6e204f7a 0x69617305 0x05050505])

;; ## testPKCS7pad
;; Test the PKCS7pad implementation
(deftest testPKCS7pad
  (testing "Padding"
    (testing "AES"
      (is (= res-128 (padder/pad PKCS7pad test-bytes Aes)))
      (is (= res-name (padder/pad PKCS7pad name-bytes Aes))))
    (testing "Blowfish"
      (is (= res-64 (padder/pad PKCS7pad test-bytes Blowfish)))
      (is (= res-name (padder/pad PKCS7pad name-bytes Blowfish))))
    (testing "Twofish"
      (is (= res-128 (padder/pad PKCS7pad test-bytes Twofish)))
      (is (= res-name (padder/pad PKCS7pad name-bytes Twofish)))))
  (testing "Unpadding"
    (testing "AES"
      (let [aes-unpad1 (padder/unpad PKCS7pad res-128 Aes)
            aes-unpad2 (padder/unpad PKCS7pad res-name Aes)]
        (is (every? true? (map = test-bytes aes-unpad1)))
        (is (every? true? (map = name-bytes aes-unpad2)))))))
