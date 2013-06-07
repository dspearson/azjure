;; ## Test Padding Methods
;; Test suite for padding methods
(ns ^{:author "Jason Ozias"}
  org.azjure.padding.testpad
  (:require [clojure.test :refer :all]
            (org.azjure.cipher [blowfish :refer (->Blowfish)]
                               [twofish :refer (->Twofish)])
            (org.azjure.padding [zeropad :refer (->Zeropad)]
                                [pkcs7pad :refer (->PKCS7pad)]
                                [x923pad :refer (->X923pad)]
                                [iso10126pad :refer (->ISO10126pad)]
                                [iso7816pad :refer (->ISO7816pad)]
                                [pad :as padder])))

;; #### PKCS7, ZERO, X923, ISO10126, ISO7816
;; Setup the Pad records for usage in tests
(def PKCS7 (->PKCS7pad))
(def ZERO (->Zeropad))
(def X923 (->X923pad))
(def ISO10126 (->ISO10126pad))
(def ISO7816 (->ISO7816pad))

;; #### BF, TF
;; Setup some cipher records for usage in tests
;; Blowfish is a 64-bit block, Twofish is 128-bit block
(def BF (->Blowfish))
(def TF (->Twofish))

;; #### test-bytes
;; A sample byte array of length two, initialize to
;;
;;     [0x01 0x02]
;;
(def test-bytes (byte-array 2 [(byte 0x01) (byte 0x02)]))

;; #### name-bytes
;; A sample byte array generated from the UTF-8 bytes of my
;; name
(def name-bytes (.getBytes "Jason Ozias" "UTF-8"))

;; #### bf-test-vectors
;; Blowfish test vectors
(def bf-test-vectors
  [[BF PKCS7   test-bytes [0x01 0x02 0x06 0x06 0x06 0x06 0x06 0x06]]
   [BF PKCS7   name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x05 0x05 0x05 0x05 0x05]]
   [BF ZERO    test-bytes [0x01 0x02 0x00 0x00 0x00 0x00 0x00 0x00]]
   [BF ZERO    name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x00 0x00 0x00 0x00 0x00]]
   [BF X923    test-bytes [0x01 0x02 0x00 0x00 0x00 0x00 0x00 0x06]]
   [BF X923    name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x00 0x00 0x00 0x00 0x05]]
   [BF ISO7816 test-bytes [0x01 0x02 0x80 0x00 0x00 0x00 0x00 0x00]]
   [BF ISO7816 name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x80 0x00 0x00 0x00 0x00]]])

;; #### tf-test-vectors
;; Twofish test vectors
(def tf-test-vectors
  [[TF PKCS7   test-bytes [0x01 0x02 0x0E 0x0E 0x0E 0x0E 0x0E 0x0E
                           0x0E 0x0E 0x0E 0x0E 0x0E 0x0E 0x0E 0x0E]]
   [TF PKCS7   name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x05 0x05 0x05 0x05 0x05]]
   [TF ZERO    test-bytes [0x01 0x02 0x00 0x00 0x00 0x00 0x00 0x00
                           0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]]
   [TF ZERO    name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x00 0x00 0x00 0x00 0x00]]
   [TF X923    test-bytes [0x01 0x02 0x00 0x00 0x00 0x00 0x00 0x00
                           0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x0E]]
   [TF X923    name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x00 0x00 0x00 0x00 0x05]]
   [TF ISO7816 test-bytes [0x01 0x02 0x80 0x00 0x00 0x00 0x00 0x00
                           0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]]
   [TF ISO7816 name-bytes [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
                           0x69 0x61 0x73 0x80 0x00 0x00 0x00 0x00]]])

;; ### padder
;; Helper function to use during padding tests
(defn- padder [[cipher padder bytes expected] & {:keys [test] :or {test (partial =)}}]
  (->> (padder/pad padder (vec bytes) cipher)
       test
       (is)))

;; ### unpadder
;; Helper function to use during unpadding tests
(defn- unpadder [[cipher padder bytes expected]]
  (->> (padder/unpad padder expected)
       (mapv byte)
       (byte-array)
       (map = bytes)
       (every? true?)
       (is)))

;; ### testPadding
;; Test the padding implementations
(deftest testPadding
  (testing "Blowfish"
    (is (= true (every? true? (map padder bf-test-vectors))))
    (is (= true (every? true? (map unpadder bf-test-vectors))))
    (testing "ISO10126"
      (let [bfpad1 (padder/pad ISO10126 (vec test-bytes) BF)
            bfpad2 (padder/pad ISO10126 (vec name-bytes) BF)]
        (is (and (= 8 (count bfpad1)) (= 6 (last bfpad1))))
        (is (and (= 16 (count bfpad2)) (= 5 (last bfpad2))))
        (->> [[BF ISO10126 test-bytes bfpad1]
              [BF ISO10126 name-bytes bfpad2]]
             (map unpadder)
             (every? true?)
             (= true)
             (is)))))
  (testing "Twofish"
    (is (= true (every? true? (map padder tf-test-vectors))))
    (is (= true (every? true? (map unpadder tf-test-vectors))))
    (testing "ISO10126"
      (let [tfpad1 (padder/pad ISO10126 (vec test-bytes) TF)
            tfpad2 (padder/pad ISO10126 (vec name-bytes) TF)]
        (is (and (= 16 (count tfpad1)) (= 14 (last tfpad1))))
        (is (and (= 16 (count tfpad2)) (= 5 (last tfpad2))))
        (->> [[TF ISO10126 test-bytes tfpad1]
              [TF ISO10126 name-bytes tfpad2]]
             (map unpadder)
             (every? true?)
             (= true)
             (is))))))
