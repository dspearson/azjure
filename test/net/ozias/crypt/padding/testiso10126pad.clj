;; # Test ISO 10126 Padding
;; Test suite for ISO 10126 padding
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.testiso10126pad
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.libbyte :refer (last-byte)]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.cipher.twofish :refer (->Twofish)]
            [net.ozias.crypt.padding.iso10126pad :refer (->ISO10126pad)]
            [net.ozias.crypt.padding.pad :as padder]))

;; ### ISO10126pad
;; Setup the ISO10126pad record for usage in tests
(def ISO10126pad (->ISO10126pad))
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

;; ## testISO10126pad
;; Test the ISO10126pad implementation
(deftest testISO10126pad
  (testing "Padding"
    (testing "AES"
      (let [aespad1 (padder/pad ISO10126pad test-bytes Aes)
            aespad2 (padder/pad ISO10126pad name-bytes Aes)]
        (is (and 
             (= 4 (count aespad1))
             (= 14 (last-byte (last aespad1)))))
        (is (and 
             (= 4 (count aespad2))
             (= 5 (last-byte (last aespad2)))))))
    (testing "Blowfish"
      (let [bfpad1 (padder/pad ISO10126pad test-bytes Blowfish)
            bfpad2 (padder/pad ISO10126pad name-bytes Blowfish)]
        (is (and 
             (= 2 (count bfpad1))
             (= 6 (last-byte (last bfpad1)))))
        (is (and 
             (= 4 (count bfpad2))
             (= 5 (last-byte (last bfpad2)))))))
    (testing "Twofish"
      (let [tfpad1 (padder/pad ISO10126pad test-bytes Twofish)
            tfpad2 (padder/pad ISO10126pad name-bytes Twofish)]
        (is (and 
             (= 4 (count tfpad1))
             (= 14 (last-byte (last tfpad1)))))
        (is (and 
             (= 4 (count tfpad2))
             (= 5 (last-byte (last tfpad2))))))))
  (testing "Unpadding"
    (testing "AES"
      (let [aes-pad1 (padder/pad ISO10126pad test-bytes Aes)
            aes-pad2 (padder/pad ISO10126pad name-bytes Aes)
            aes-unpad1 (padder/unpad ISO10126pad aes-pad1 Aes)
            aes-unpad2 (padder/unpad ISO10126pad aes-pad2 Aes)]
        (is (every? true? (map = test-bytes aes-unpad1)))
        (is (every? true? (map = name-bytes aes-unpad2)))))))
