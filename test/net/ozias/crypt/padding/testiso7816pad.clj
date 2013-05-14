;; # Test ISO7816 Padding
;; Test suite for ISO7816 padding
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.testiso7816pad
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.cipher.twofish :refer (->Twofish)]
            [net.ozias.crypt.padding.iso7816pad :refer (->ISO7816pad)]
            [net.ozias.crypt.padding.pad :as padder]))

;; ### ISO7816pad
;; Setup the ISO7816pad record for usage in tests
(def ISO7816pad (->ISO7816pad))
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
(def res-64 [0x01028000 0x0])
;; ### res-128
;; The expected result of padding the test-bytes array
;; to the proper size for a 128-bit blocksize cipher
(def res-128 [0x01028000 0x0 0x0 0x0])
;; ### res-name
;; The expected result of padding the name-bytes array
;; to the proper size for a 64-bit or 128-bit blocksize cipher
(def res-name [0x4a61736f 0x6e204f7a 0x69617380 0x0])

;; ## testISO7816pad
;; Test the ISO7816pad implementation
(deftest testISO7816pad
  (testing "Padding"
    (testing "AES"
      (is (= res-128 (padder/pad ISO7816pad test-bytes Aes)))
      (is (= res-name (padder/pad ISO7816pad name-bytes Aes))))
    (testing "Blowfish"
      (is (= res-64 (padder/pad ISO7816pad test-bytes Blowfish)))
      (is (= res-name (padder/pad ISO7816pad name-bytes Blowfish))))
    (testing "Twofish"
      (is (= res-128 (padder/pad ISO7816pad test-bytes Twofish)))
      (is (= res-name (padder/pad ISO7816pad name-bytes Twofish))))))
