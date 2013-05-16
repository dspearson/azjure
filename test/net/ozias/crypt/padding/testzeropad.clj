;; # Test Zeropad Padding
;; Test suite for Zero padding
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.testzeropad
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.cipher.twofish :refer (->Twofish)]
            [net.ozias.crypt.padding.zeropad :refer (->Zeropad)]
            [net.ozias.crypt.padding.pad :as padder]))

;; ### Zeropad
;; Setup the Zeropad record for usage in tests
(def Zeropad (->Zeropad))
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
(def res-64 [0x01020000 0x0])
;; ### res-128
;; The expected result of padding the test-bytes array
;; to the proper size for a 128-bit blocksize cipher
(def res-128 [0x01020000 0x0 0x0 0x0])
;; ### res-name
;; The expected result of padding the name-bytes array
;; to the proper size for a 64-bit or 128-bit blocksize cipher
(def res-name [0x4a61736f 0x6e204f7a 0x69617300 0x00000000])

;; ## testZeropad
;; Test the Zeropad implementation
(deftest testZeropad
  (testing "Padding"
    (testing "AES"
      (is (= res-128 (padder/pad Zeropad test-bytes Aes)))
      (is (= res-name (padder/pad Zeropad name-bytes Aes))))
    (testing "Blowfish"
      (is (= res-64 (padder/pad Zeropad test-bytes Blowfish)))
      (is (= res-name (padder/pad Zeropad name-bytes Blowfish))))
    (testing "Twofish"
      (is (= res-128 (padder/pad Zeropad test-bytes Twofish)))
      (is (= res-name (padder/pad Zeropad name-bytes Twofish)))))
  (testing "Unpadding"
    (testing "AES"
      (let [aes-unpad1 (padder/unpad Zeropad res-128 Aes)
            aes-unpad2 (padder/unpad Zeropad res-name Aes)]
        (is (every? true? (map = test-bytes aes-unpad1)))
        (is (every? true? (map = name-bytes aes-unpad2)))))
    (testing "Blowfish"
      (let [bf-unpad1 (padder/unpad Zeropad res-128 Blowfish)
            bf-unpad2 (padder/unpad Zeropad res-name Blowfish)]
        (is (every? true? (map = test-bytes bf-unpad1)))
        (is (every? true? (map = name-bytes bf-unpad2)))))))
