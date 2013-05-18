;; ## Test Crypt Suites
;; Test the crypt suites (e.g. AES/CBC/PKCS7)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testcryptsuite
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.libbyte :refer (last-byte)]
            (net.ozias.crypt [cryptsuite :as cs]
                             [cryptsuite :refer (->AESECBPKCS7)]
                             [cryptsuite :refer (->AESECBZERO)]
                             [cryptsuite :refer (->AESECBISO10126)]
                             [cryptsuite :refer (->AESECBX923)]
                             [cryptsuite :refer (->AESECBISO7816)]
                             [cryptsuite :refer (->AESCBCPKCS7)]
                             [cryptsuite :refer (->AESCBCZERO)]
                             [cryptsuite :refer (->AESCBCISO10126)]
                             [cryptsuite :refer (->AESCBCX923)]
                             [cryptsuite :refer (->AESCBCISO7816)]
                             [cryptsuite :refer (->AESPCBCPKCS7)]
                             [cryptsuite :refer (->AESPCBCZERO)]
                             [cryptsuite :refer (->AESPCBCISO10126)]
                             [cryptsuite :refer (->AESPCBCX923)]
                             [cryptsuite :refer (->AESPCBCISO7816)]
                             [cryptsuite :refer (->AESCFBPKCS7)]
                             [cryptsuite :refer (->AESCFBZERO)]
                             [cryptsuite :refer (->AESCFBISO10126)]
                             [cryptsuite :refer (->AESCFBX923)]
                             [cryptsuite :refer (->AESCFBISO7816)]
                             [cryptsuite :refer (->AESOFBPKCS7)]
                             [cryptsuite :refer (->AESOFBZERO)]
                             [cryptsuite :refer (->AESOFBISO10126)]
                             [cryptsuite :refer (->AESOFBX923)]
                             [cryptsuite :refer (->AESOFBISO7816)]
                             [cryptsuite :refer (->BFECBPKCS7)]
                             [cryptsuite :refer (->BFECBZERO)]
                             [cryptsuite :refer (->BFECBISO10126)]
                             [cryptsuite :refer (->BFECBX923)]
                             [cryptsuite :refer (->BFECBISO7816)]
                             [cryptsuite :refer (->BFCBCPKCS7)]
                             [cryptsuite :refer (->BFCBCZERO)]
                             [cryptsuite :refer (->BFCBCISO10126)]
                             [cryptsuite :refer (->BFCBCX923)]
                             [cryptsuite :refer (->BFCBCISO7816)]
                             [cryptsuite :refer (->BFPCBCPKCS7)]
                             [cryptsuite :refer (->BFCFBX923)])
            (net.ozias.crypt [testivs :refer (iv-128)]
                             [testkeys :refer (key-128)])))

;; #### AESXX
;; Setup the AES suites for use in testing.
(def AESECBPKCS7 (->AESECBPKCS7))
(def AESECBZERO (->AESECBZERO))
(def AESECBISO10126 (->AESECBISO10126))
(def AESECBX923 (->AESECBX923))
(def AESECBISO7816 (->AESECBISO7816))
(def AESCBCPKCS7 (->AESCBCPKCS7))
(def AESCBCZERO (->AESCBCZERO))
(def AESCBCISO10126 (->AESCBCISO10126))
(def AESCBCX923 (->AESCBCX923))
(def AESCBCISO7816 (->AESCBCISO7816))
(def AESPCBCPKCS7 (->AESPCBCPKCS7))
(def AESPCBCZERO (->AESPCBCZERO))
(def AESPCBCISO10126 (->AESPCBCISO10126))
(def AESPCBCX923 (->AESCBCX923))
(def AESPCBCISO7816 (->AESPCBCISO7816))
(def AESCFBPKCS7 (->AESCFBPKCS7))
(def AESCFBZERO (->AESCFBZERO))
(def AESCFBISO10126 (->AESCFBISO10126))
(def AESCFBX923 (->AESCFBX923))
(def AESCFBISO7816 (->AESCFBISO7816))
(def AESOFBPKCS7 (->AESOFBPKCS7))
(def AESOFBZERO (->AESOFBZERO))
(def AESOFBISO10126 (->AESOFBISO10126))
(def AESOFBX923 (->AESOFBX923))
(def AESOFBISO7816 (->AESOFBISO7816))

;; #### BFXX
;; Setup the Blowfish suites for use in testing.
(def BFECBPKCS7 (->BFECBPKCS7))
(def BFECBZERO (->BFECBZERO))
(def BFECBISO10126 (->BFECBISO10126))
(def BFECBX923 (->BFECBX923))
(def BFECBISO7816 (->BFECBISO7816))
(def BFCBCPKCS7 (->BFCBCPKCS7))
(def BFCBCZERO (->BFCBCZERO))
(def BFCBCISO10126 (->BFCBCISO10126))
(def BFCBCX923 (->BFCBCX923))
(def BFCBCISO7816 (->BFCBCISO7816))
(def BFPCBCPKCS7 (->BFPCBCPKCS7))
(def BFCFBX923 (->BFCFBX923))

;; #### name-bytes
;; My name as a byte array of UTF-8 bytes
(def myname "Jason Ozias")
(def phrase "The quick brown fox jumps over the lazy dog.")

;; #### aes-test-vectors
;; Test vectors for each supported AES suite
(def aes-test-vectors
  [[AESECBPKCS7   myname [0x9e94c4e4 0x1336d233 0xdff541da 0xf087c9a7]]
   [AESECBZERO    myname [0x007aabf0 0x7a9b9c1d 0x5d222885 0xd4b51dcc]]
   [AESECBX923    myname [0x4609ef72 0xcec01435 0x711663f8 0x1aa876ec]]
   [AESECBISO7816 myname [0xe9ba8e42 0xf496b5d7 0x040f3be3 0xe600380e]]
   [AESCBCPKCS7   myname [0x184a08c1 0x04d97f63 0xd1692da5 0x01193b83]]
   [AESCBCZERO    myname [0x9d02ac5f 0xef9aae8d 0x4170955d 0xb8a83e91]]
   [AESCBCX923    myname [0x52c34aae 0x9e4d5953 0xd0f05a65 0xafbc56e2]]
   [AESCBCISO7816 myname [0x87fc70c4 0x143941f7 0xbdc8cc55 0x36a09c7e]]
   [AESPCBCPKCS7  myname [0x184a08c1 0x04d97f63 0xd1692da5 0x01193b83]]
   [AESECBPKCS7   phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3 
                          0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
                          0xe209d7a1 0x8ed8ce63 0xf8675723 0xfa5ad724]]
   [AESCFBX923    phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a 
                          0x909aaeaf 0xd74ac79e 0xa57df7ec 0x2335425d 
                          0x507955a2 0x7cb036be 0x384b28ae 0xfd66ae68]]
   [AESOFBPKCS7   phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                          0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                          0xe3f93f7e 0x5616fedd 0xd4e45260 0x44458b99]]
   [AESOFBZERO    phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                          0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                          0xe3f93f7e 0x5616fedd 0xd4e45260 0x40418f9d]]
   [AESOFBX923    phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                          0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                          0xe3f93f7e 0x5616fedd 0xd4e45260 0x40418f99]]
   [AESOFBISO7816 phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                          0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                          0xe3f93f7e 0x5616fedd 0xd4e45260 0xc0418f9d]]])

;; #### bf-test-vectors
;; Test vectors for each supported Blowfish suite
(def bf-test-vectors
  [[BFECBPKCS7   myname [0x615b80bf 0xd8d093b3 0x8db20d6d 0xd1ef46c3]]
   [BFECBZERO    myname [0x615b80bf 0xd8d093b3 0x70aa0c4d 0x9abf4d20]]
   [BFECBX923    myname [0x615b80bf 0xd8d093b3 0xc517e502 0xbbb74029]]
   [BFECBISO7816 myname [0x615b80bf 0xd8d093b3 0x7e2f9dfc 0x6d943806]]
   [BFCBCPKCS7   myname [0x47b754e6 0xddeaff3f 0x37af8d49 0xf5e0e239]]
   [BFCBCZERO    myname [0x47b754e6 0xddeaff3f 0x6928b01d 0x842403d9]]
   [BFCBCX923    myname [0x47b754e6 0xddeaff3f 0x16c11f09 0xa23a4d3d]]
   [BFCBCISO7816 myname [0x47b754e6 0xddeaff3f 0xa1788ec7 0xd5f3796c]]
   [BFPCBCPKCS7  myname [0x47b754e6 0xddeaff3f 0xc8b2f7e3 0x847c38a3]]
   [BFCBCPKCS7   phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f 
                         0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6 
                         0x55c680fe 0xabaae236 0x36ff9ff8 0xcf85485f]]
   [BFCFBX923    phrase [0x42ad61bf 0x4f4fba35 0xda835c75 0x04448db7
                         0x0f7e4bc9 0x1c790660 0xa69b927b 0x1813d5f6
                         0x57dede33 0xf9b441b5 0x185cfecc 0xf740a3cf]]])

(defn- encryptor [[suite pt ct]]
  (is (= ct (cs/encrypt suite key-128 iv-128 (.getBytes pt "UTF-8")))))

(defn- decryptor [[suite pt ct]]
  (is (= pt (String. (cs/decrypt suite key-128 iv-128 ct) "UTF-8"))))

;; ### testSuites
;; Test the various cipher suites.
(deftest testSuites
  (testing "AES"
    (is (= true (every? true? (map #(encryptor %) aes-test-vectors))))
    (is (= true (every? true? (map #(decryptor %) aes-test-vectors)))))
  (testing "Blowfish"
    (is (= true (every? true? (map #(encryptor %) bf-test-vectors))))
    (is (= true (every? true? (map #(decryptor %) bf-test-vectors))))))
