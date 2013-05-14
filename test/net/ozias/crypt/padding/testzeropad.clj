(ns net.ozias.crypt.padding.testzeropad
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.padding.zeropad :refer (->Zeropad)]
            [net.ozias.crypt.padding.pad :as padder]))

(def Zeropad (->Zeropad))
(def Aes (->Aes))
(def Blowfish (->Blowfish))

(def test-bytes (byte-array 2 [(byte 0x01) (byte 0x02)]))
(def bf-result [0x01020000 0x0])
(def aes-result [0x01020000 0x0 0x0 0x0])
(def name-bytes (.getBytes "Jason Ozias" "UTF-8"))
(def bf-name-result [0x4a61736f 0x6e204f7a 0x69617300 0x00000000])
(def aes-name-result [0x4a61736f 0x6e204f7a 0x69617300 0x00000000])

(deftest testZeropad
  (testing "Padding"
    (is (= bf-result (padder/pad-blocks Zeropad test-bytes Blowfish)))
    (is (= bf-name-result (padder/pad-blocks Zeropad name-bytes Blowfish)))
    (is (= aes-result (padder/pad-blocks Zeropad test-bytes Aes)))
    (is (= aes-name-result (padder/pad-blocks Zeropad name-bytes Aes)))))
