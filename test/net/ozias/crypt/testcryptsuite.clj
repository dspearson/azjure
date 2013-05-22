;; ## Test Crypt Suites
;; Test the crypt suites (e.g. AES/CBC/PKCS7)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testcryptsuite
  (:require [clojure.test :refer :all]
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
                             [cryptsuite :refer (->BFPCBCZERO)]
                             [cryptsuite :refer (->BFPCBCISO10126)]
                             [cryptsuite :refer (->BFPCBCX923)]
                             [cryptsuite :refer (->BFPCBCISO7816)]
                             [cryptsuite :refer (->BFCFBPKCS7)]
                             [cryptsuite :refer (->BFCFBZERO)]
                             [cryptsuite :refer (->BFCFBISO10126)]
                             [cryptsuite :refer (->BFCFBX923)]
                             [cryptsuite :refer (->BFCFBISO7816)]
                             [cryptsuite :refer (->BFOFBPKCS7)]
                             [cryptsuite :refer (->BFOFBZERO)]
                             [cryptsuite :refer (->BFOFBISO10126)]
                             [cryptsuite :refer (->BFOFBX923)]
                             [cryptsuite :refer (->BFOFBISO7816)]
                             [cryptsuite :refer (->CAST5ECBPKCS7)]
                             [cryptsuite :refer (->CAST5ECBZERO)]
                             [cryptsuite :refer (->CAST5ECBISO10126)]
                             [cryptsuite :refer (->CAST5ECBX923)]
                             [cryptsuite :refer (->CAST5ECBISO7816)]
                             [cryptsuite :refer (->CAST5CBCPKCS7)]
                             [cryptsuite :refer (->CAST5CBCZERO)]
                             [cryptsuite :refer (->CAST5CBCISO10126)]
                             [cryptsuite :refer (->CAST5CBCX923)]
                             [cryptsuite :refer (->CAST5CBCISO7816)]
                             [cryptsuite :refer (->CAST5PCBCPKCS7)]
                             [cryptsuite :refer (->CAST5PCBCZERO)]
                             [cryptsuite :refer (->CAST5PCBCISO10126)]
                             [cryptsuite :refer (->CAST5PCBCX923)]
                             [cryptsuite :refer (->CAST5PCBCISO7816)]
                             [cryptsuite :refer (->CAST5CFBPKCS7)]
                             [cryptsuite :refer (->CAST5CFBZERO)]
                             [cryptsuite :refer (->CAST5CFBISO10126)]
                             [cryptsuite :refer (->CAST5CFBX923)]
                             [cryptsuite :refer (->CAST5CFBISO7816)]
                             [cryptsuite :refer (->CAST5OFBPKCS7)]
                             [cryptsuite :refer (->CAST5OFBZERO)]
                             [cryptsuite :refer (->CAST5OFBISO10126)]
                             [cryptsuite :refer (->CAST5OFBX923)]
                             [cryptsuite :refer (->CAST5OFBISO7816)]
                             [cryptsuite :refer (->CAST6ECBPKCS7)]
                             [cryptsuite :refer (->CAST6ECBZERO)]
                             [cryptsuite :refer (->CAST6ECBISO10126)]
                             [cryptsuite :refer (->CAST6ECBX923)]
                             [cryptsuite :refer (->CAST6ECBISO7816)]
                             [cryptsuite :refer (->CAST6CBCPKCS7)]
                             [cryptsuite :refer (->CAST6CBCZERO)]
                             [cryptsuite :refer (->CAST6CBCISO10126)]
                             [cryptsuite :refer (->CAST6CBCX923)]
                             [cryptsuite :refer (->CAST6CBCISO7816)]
                             [cryptsuite :refer (->CAST6PCBCPKCS7)]
                             [cryptsuite :refer (->CAST6PCBCZERO)]
                             [cryptsuite :refer (->CAST6PCBCISO10126)]
                             [cryptsuite :refer (->CAST6PCBCX923)]
                             [cryptsuite :refer (->CAST6PCBCISO7816)]
                             [cryptsuite :refer (->CAST6CFBPKCS7)]
                             [cryptsuite :refer (->CAST6CFBZERO)]
                             [cryptsuite :refer (->CAST6CFBISO10126)]
                             [cryptsuite :refer (->CAST6CFBX923)]
                             [cryptsuite :refer (->CAST6CFBISO7816)]
                             [cryptsuite :refer (->CAST6OFBPKCS7)]
                             [cryptsuite :refer (->CAST6OFBZERO)]
                             [cryptsuite :refer (->CAST6OFBISO10126)]
                             [cryptsuite :refer (->CAST6OFBX923)]
                             [cryptsuite :refer (->CAST6OFBISO7816)])
            (net.ozias.crypt [testivs :refer (iv-128)]
                             [testkeys :refer (key-128 key-128b)])))

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
(def BFPCBCZERO (->BFPCBCZERO))
(def BFPCBCISO10126 (->BFPCBCISO10126))
(def BFPCBCX923 (->BFPCBCX923))
(def BFPCBCISO7816 (->BFPCBCISO7816))
(def BFCFBPKCS7 (->BFCFBPKCS7))
(def BFCFBZERO (->BFCFBZERO))
(def BFCFBISO10126 (->BFCFBISO10126))
(def BFCFBX923 (->BFCFBX923))
(def BFCFBISO7816 (->BFCFBISO7816))
(def BFOFBPKCS7 (->BFOFBPKCS7))
(def BFOFBZERO (->BFOFBZERO))
(def BFOFBISO10126 (->BFOFBISO10126))
(def BFOFBX923 (->BFOFBX923))
(def BFOFBISO7816 (->BFOFBISO7816))

;; #### CAST5XX
;; Setup the Blowfish suites for use in testing.
(def CAST5ECBPKCS7 (->CAST5ECBPKCS7))
(def CAST5ECBZERO (->CAST5ECBZERO))
(def CAST5ECBISO10126 (->CAST5ECBISO10126))
(def CAST5ECBX923 (->CAST5ECBX923))
(def CAST5ECBISO7816 (->CAST5ECBISO7816))
(def CAST5CBCPKCS7 (->CAST5CBCPKCS7))
(def CAST5CBCZERO (->CAST5CBCZERO))
(def CAST5CBCISO10126 (->CAST5CBCISO10126))
(def CAST5CBCX923 (->CAST5CBCX923))
(def CAST5CBCISO7816 (->CAST5CBCISO7816))
(def CAST5PCBCPKCS7 (->CAST5PCBCPKCS7))
(def CAST5PCBCZERO (->CAST5PCBCZERO))
(def CAST5PCBCISO10126 (->CAST5PCBCISO10126))
(def CAST5PCBCX923 (->CAST5PCBCX923))
(def CAST5PCBCISO7816 (->CAST5PCBCISO7816))
(def CAST5CFBPKCS7 (->CAST5CFBPKCS7))
(def CAST5CFBZERO (->CAST5CFBZERO))
(def CAST5CFBISO10126 (->CAST5CFBISO10126))
(def CAST5CFBX923 (->CAST5CFBX923))
(def CAST5CFBISO7816 (->CAST5CFBISO7816))
(def CAST5OFBPKCS7 (->CAST5OFBPKCS7))
(def CAST5OFBZERO (->CAST5OFBZERO))
(def CAST5OFBISO10126 (->CAST5OFBISO10126))
(def CAST5OFBX923 (->CAST5OFBX923))
(def CAST5OFBISO7816 (->CAST5OFBISO7816))

;; #### CAST6XX
;; Setup the Blowfish suites for use in testing.
(def CAST6ECBPKCS7 (->CAST6ECBPKCS7))
(def CAST6ECBZERO (->CAST6ECBZERO))
(def CAST6ECBISO10126 (->CAST6ECBISO10126))
(def CAST6ECBX923 (->CAST6ECBX923))
(def CAST6ECBISO7816 (->CAST6ECBISO7816))
(def CAST6CBCPKCS7 (->CAST6CBCPKCS7))
(def CAST6CBCZERO (->CAST6CBCZERO))
(def CAST6CBCISO10126 (->CAST6CBCISO10126))
(def CAST6CBCX923 (->CAST6CBCX923))
(def CAST6CBCISO7816 (->CAST6CBCISO7816))
(def CAST6PCBCPKCS7 (->CAST6PCBCPKCS7))
(def CAST6PCBCZERO (->CAST6PCBCZERO))
(def CAST6PCBCISO10126 (->CAST6PCBCISO10126))
(def CAST6PCBCX923 (->CAST6PCBCX923))
(def CAST6PCBCISO7816 (->CAST6PCBCISO7816))
(def CAST6CFBPKCS7 (->CAST6CFBPKCS7))
(def CAST6CFBZERO (->CAST6CFBZERO))
(def CAST6CFBISO10126 (->CAST6CFBISO10126))
(def CAST6CFBX923 (->CAST6CFBX923))
(def CAST6CFBISO7816 (->CAST6CFBISO7816))
(def CAST6OFBPKCS7 (->CAST6OFBPKCS7))
(def CAST6OFBZERO (->CAST6OFBZERO))
(def CAST6OFBISO10126 (->CAST6OFBISO10126))
(def CAST6OFBX923 (->CAST6OFBX923))
(def CAST6OFBISO7816 (->CAST6OFBISO7816))

;; #### phrase
;; A phrase to test encryption/decryption
(def phrase "The quick brown fox jumps over the lazy dog.")

;; #### aes-test-vectors
;; Test vectors for each supported AES suite
(def aes-test-vectors
  [[AESECBPKCS7    phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3 
                           0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
                           0xe209d7a1 0x8ed8ce63 0xf8675723 0xfa5ad724]]
   [AESECBZERO     phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3
                           0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
                           0x7ddec538 0xe17e374a 0x508b2017 0x049c3da2]]
   [AESECBX923     phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3
                           0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
                           0x02d49cad 0xc52018ff 0x0b05bea9 0x9d784d60]]
   [AESECBISO7816  phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3
                           0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
                           0xba27b732 0xc37be65e 0xd25d5757 0x1c012345]]
   [AESCBCPKCS7    phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
                           0xff946ab7 0xaab76b32 0x37aeea72 0x9f1dd4e6]]
   [AESCBCZERO     phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
                           0x4d9e0980 0x771d7593 0x760a7388 0xfdf7230f]]
   [AESCBCX923     phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
                           0xfc80314b 0xcb3b582 0xd806fce8 0xb9ad034e]]
   [AESCBCISO7816  phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
                           0x5b19892e 0x23e65691 0x2eea077b 0x6a68e32c]]
   [AESPCBCPKCS7   phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0x8d8ed276 0xb6970681 0x95830e5f 0x468add9f
                           0x08397b9d 0xb6d327f8 0x8551a7e5 0xb8de5be]]
   [AESPCBCZERO    phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0x8d8ed276 0xb6970681 0x95830e5f 0x468add9f
                           0xf8a5393a 0x6c0cfb7c 0xd52f5b2c 0xb9596671]]
   [AESPCBCX923    phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
                           0xfc80314b 0xcb3b582 0xd806fce8 0xb9ad034e]]
   [AESPCBCISO7816 phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
                           0x8d8ed276 0xb6970681 0x95830e5f 0x468add9f
                           0x6d546556 0xcf704c73 0xa81672e7 0x63a686a6]]
   [AESCFBPKCS7    phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                           0x909aaeaf 0xd74ac79e 0xa57df7ec 0x2335425d
                           0x507955a2 0x7cb036be 0x384b28ae 0xf962aa68]]
   [AESCFBZERO     phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                           0x909aaeaf 0xd74ac79e 0xa57df7ec 0x2335425d
                           0x507955a2 0x7cb036be 0x384b28ae 0xfd66ae6c]]
   [AESCFBX923     phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a 
                           0x909aaeaf 0xd74ac79e 0xa57df7ec 0x2335425d 
                           0x507955a2 0x7cb036be 0x384b28ae 0xfd66ae68]]
   [AESCFBISO7816  phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                           0x909aaeaf 0xd74ac79e 0xa57df7ec 0x2335425d
                           0x507955a2 0x7cb036be 0x384b28ae 0x7d66ae6c]]
   [AESOFBPKCS7    phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                           0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                           0xe3f93f7e 0x5616fedd 0xd4e45260 0x44458b99]]
   [AESOFBZERO     phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                           0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                           0xe3f93f7e 0x5616fedd 0xd4e45260 0x40418f9d]]
   [AESOFBX923     phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                           0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                           0xe3f93f7e 0x5616fedd 0xd4e45260 0x40418f99]]
   [AESOFBISO7816  phrase [0x74c19cb2 0xc539328b 0x6f3f9eae 0x03d9f74a
                           0x8261554f 0x2d17cdb5 0xf72444fd 0xb046503f
                           0xe3f93f7e 0x5616fedd 0xd4e45260 0xc0418f9d]]])

;; #### bf-test-vectors
;; Test vectors for each supported Blowfish suite
(def bf-test-vectors
  [[BFECBPKCS7    phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
                          0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
                          0x0d9c9da2 0x58b94843 0x12ddbdf0 0x75fe5aaa]]
   [BFECBZERO     phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
                          0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
                          0x0d9c9da2 0x58b94843 0x8e2a98a9 0xd6cda8c9]]
   [BFECBX923     phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
                          0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
                          0x0d9c9da2 0x58b94843 0xa4fdbf45 0x7a9ef177]]
   [BFECBISO7816  phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
                          0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
                          0x0d9c9da2 0x58b94843 0x2a619282 0xd291a306]]
   [BFCBCPKCS7    phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f 
                          0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6 
                          0x55c680fe 0xabaae236 0x36ff9ff8 0xcf85485f]]
   [BFCBCZERO     phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f
                          0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6
                          0x55c680fe 0xabaae236 0x795fdd05 0xda068fa1]]
   [BFCBCX923     phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f
                          0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6
                          0x55c680fe 0xabaae236 0xde262374 0xae26f17f]]
   [BFCBCISO7816  phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f
                          0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6
                          0x55c680fe 0xabaae236 0x16b373c6 0xf532798e]]
   [BFPCBCPKCS7   phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
                          0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
                          0x6c52a2ba 0x7dbcbf67 0x2b85eb8e 0xe8ab37ee]]
   [BFPCBCZERO    phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
                          0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
                          0x6c52a2ba 0x7dbcbf67 0x13ea40c1 0x29c0805d]]
   [BFPCBCX923    phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
                          0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
                          0x6c52a2ba 0x7dbcbf67 0xe844a968 0x4d082c19]]
   [BFPCBCISO7816 phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
                          0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
                          0x6c52a2ba 0x7dbcbf67 0xf13abe40 0x12fa8b32]]
   [BFCFBPKCS7    phrase [0x42ad61bf 0x4f4fba35 0xda835c75 0x04448db7
                          0x0f7e4bc9 0x1c790660 0xa69b927b 0x1813d5f6
                          0x57dede33 0xf9b441b5 0x185cfecc 0xf344a7cf]]
   [BFCFBZERO     phrase [0x42ad61bf 0x4f4fba35 0xda835c75 0x04448db7
                          0x0f7e4bc9 0x1c790660 0xa69b927b 0x1813d5f6
                          0x57dede33 0xf9b441b5 0x185cfecc 0xf740a3cb]]
   [BFCFBX923     phrase [0x42ad61bf 0x4f4fba35 0xda835c75 0x04448db7
                          0x0f7e4bc9 0x1c790660 0xa69b927b 0x1813d5f6
                          0x57dede33 0xf9b441b5 0x185cfecc 0xf740a3cf]]
   [BFCFBISO7816  phrase [0x42ad61bf 0x4f4fba35 0xda835c75 0x04448db7
                          0x0f7e4bc9 0x1c790660 0xa69b927b 0x1813d5f6
                          0x57dede33 0xf9b441b5 0x185cfecc 0x7740a3cb]]
   [BFOFBPKCS7    phrase [0x42ad61bf 0x4f4fba35 0x478c2c29 0xf7ac8328
                          0x8f6ec424 0xbbc7b53f 0x73c27ac4 0x07bb37a9
                          0x939d3bc4 0x507cc229 0x96c15780 0xfba2ad1b]]
   [BFOFBZERO     phrase [0x42ad61bf 0x4f4fba35 0x478c2c29 0xf7ac8328
                          0x8f6ec424 0xbbc7b53f 0x73c27ac4 0x07bb37a9
                          0x939d3bc4 0x507cc229 0x96c15780 0xffa6a91f]]
   [BFOFBX923     phrase [0x42ad61bf 0x4f4fba35 0x478c2c29 0xf7ac8328
                          0x8f6ec424 0xbbc7b53f 0x73c27ac4 0x07bb37a9
                          0x939d3bc4 0x507cc229 0x96c15780 0xffa6a91b]]
   [BFOFBISO7816  phrase [0x42ad61bf 0x4f4fba35 0x478c2c29 0xf7ac8328
                          0x8f6ec424 0xbbc7b53f 0x73c27ac4 0x07bb37a9
                          0x939d3bc4 0x507cc229 0x96c15780 0x7fa6a91f]]])

;; #### cast5-test-vectors
;; Test vectors for each supported CAST5 suite
(def cast5-test-vectors
  [[CAST5ECBPKCS7    phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
                             0x77222960 0x6685b5d2 0x03822655 0xfffd9170
                             0x561c926f 0x8fcedd2b 0xc7fdcf2e 0x83a687bd]]
   [CAST5ECBZERO     phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
                             0x77222960 0x6685b5d2 0x03822655 0xfffd9170
                             0x561c926f 0x8fcedd2b 0xf9bcab93 0x89b48066]]
   [CAST5ECBX923     phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
                             0x77222960 0x6685b5d2 0x03822655 0xfffd9170
                             0x561c926f 0x8fcedd2b 0xfef0bd65 0xb791c4a0]]
   [CAST5ECBISO7816  phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
                             0x77222960 0x6685b5d2 0x03822655 0xfffd9170
                             0x561c926f 0x8fcedd2b 0x78ec9bd 0x3afea3b1]]
   [CAST5CBCPKCS7    phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
                             0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
                             0xfb5f3523 0x9aea1a6a 0xf32df9da 0xd8a447e8]]
   [CAST5CBCZERO     phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
                             0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
                             0xfb5f3523 0x9aea1a6a 0x900111ee 0x532e7629]]
   [CAST5CBCX923     phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
                             0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
                             0xfb5f3523 0x9aea1a6a 0xf298698c 0x66a12e1e]]
   [CAST5CBCISO7816  phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
                             0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
                             0xfb5f3523 0x9aea1a6a 0x3013af87 0x261bea0a]]
   [CAST5PCBCPKCS7   phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
                             0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
                             0x1fc7865d 0x0ca1371b 0x23404ed 0xead34e2a]]
   [CAST5PCBCZERO    phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
                             0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
                             0x1fc7865d 0x0ca1371b 0xcb2d2cf9 0x21ec8f86]]
   [CAST5PCBCX923    phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
                             0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
                             0x1fc7865d 0x0ca1371b 0x6ccb25fa 0x9853500b]]
   [CAST5PCBCISO7816 phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
                             0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
                             0x1fc7865d 0x0ca1371b 0xdf93ffe8 0x5a976927]]
   [CAST5CFBPKCS7    phrase [0x1b1b0029 0x3700bcf8 0x5f57dd4a 0x98b85534
                             0xfe2be48b 0x68c22a89 0xb8792968 0x2b2762a7
                             0xcd881d55 0x8f8143dc 0x9344e8d7 0x6b3cc237]]
   [CAST5CFBZERO     phrase [0x1b1b0029 0x3700bcf8 0x5f57dd4a 0x98b85534
                             0xfe2be48b 0x68c22a89 0xb8792968 0x2b2762a7
                             0xcd881d55 0x8f8143dc 0x9344e8d7 0x6f38c633]]
   [CAST5CFBX923     phrase [0x1b1b0029 0x3700bcf8 0x5f57dd4a 0x98b85534
                             0xfe2be48b 0x68c22a89 0xb8792968 0x2b2762a7
                             0xcd881d55 0x8f8143dc 0x9344e8d7 0x6f38c637]]
   [CAST5CFBISO7816  phrase [0x1b1b0029 0x3700bcf8 0x5f57dd4a 0x98b85534
                             0xfe2be48b 0x68c22a89 0xb8792968 0x2b2762a7
                             0xcd881d55 0x8f8143dc 0x9344e8d7 0xef38c633]]
   [CAST5OFBPKCS7    phrase [0x1b1b0029 0x3700bcf8 0xa1e11ce6 0xf2396b6a
                             0xbd573907 0x08750c22 0xcb96decf 0x05aa54bc
                             0x663c9740 0xac905ad5 0xa0157086 0x96808fa9]]
   [CAST5OFBZERO     phrase [0x1b1b0029 0x3700bcf8 0xa1e11ce6 0xf2396b6a
                             0xbd573907 0x08750c22 0xcb96decf 0x05aa54bc
                             0x663c9740 0xac905ad5 0xa0157086 0x92848bad]]
   [CAST5OFBX923     phrase [0x1b1b0029 0x3700bcf8 0xa1e11ce6 0xf2396b6a
                             0xbd573907 0x08750c22 0xcb96decf 0x05aa54bc
                             0x663c9740 0xac905ad5 0xa0157086 0x92848ba9]]
   [CAST5OFBISO7816  phrase [0x1b1b0029 0x3700bcf8 0xa1e11ce6 0xf2396b6a
                             0xbd573907 0x08750c22 0xcb96decf 0x05aa54bc
                             0x663c9740 0xac905ad5 0xa0157086 0x12848bad]]])

;; #### cast6-test-vectors
;; Test vectors for each supported CAST6 suite
(def cast6-test-vectors
  [[CAST6ECBPKCS7    phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
                             0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
                             0xed9cf548 0x55edc7c6 0x56a94528 0xef50218f]]
   [CAST6ECBZERO     phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
                             0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
                             0x40c1394f 0x20956d67 0x012e820f 0x75a6b853]]
   [CAST6ECBX923     phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
                             0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
                             0xac17f63a 0xe8c185d2 0x909a8f2d 0x77fbbe9c]]
   [CAST6ECBISO7816  phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
                             0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
                             0xfd1b3087 0xfdc4d6c9 0xc3f301da 0xb181adfb]]
   [CAST6CBCPKCS7    phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0x633c745e 0x1940d579 0xf57bea1c 0x39486330
                             0xc59fe2d2 0x6b0b12de 0xf478a36f 0x7cd7c3bc]]
   [CAST6CBCZERO     phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0x633c745e 0x1940d579 0xf57bea1c 0x39486330
                             0xf59481a7 0x223b82c5 0x9fbee450 0x49a969cb]]
   [CAST6CBCX923     phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0x633c745e 0x1940d579 0xf57bea1c 0x39486330
                             0x80e0c88f 0x2af0abf0 0x5b960339 0x632d8b92]]
   [CAST6CBCISO7816  phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0x633c745e 0x1940d579 0xf57bea1c 0x39486330
                             0x7fa8f65e 0x10507d61 0x38a88894 0x696b5763]]
   [CAST6PCBCPKCS7   phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
                             0xf826cd2d 0x972ff4e4 0x3d32ff00 0x87ef0a7a]]
   [CAST6PCBCZERO    phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
                             0xcddd45e2 0xc924c710 0x9881fe79 0xa2ccf011]]
   [CAST6PCBCX923    phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
                             0x4824ce3a 0x98bafc05 0xd5db54d4 0x76b6512c]]
   [CAST6PCBCISO7816 phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
                             0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
                             0x8a91d9d0 0x0b6c3527 0x02876a9c 0x00ee1032]]
   [CAST6CFBPKCS7    phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0x511f1f9b 0xf830f7ea 0x338f588d 0xcee47d83
                             0x6e379438 0x2ffd710a 0xf7919f09 0xfbb3c775]]
   [CAST6CFBZERO     phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0x511f1f9b 0xf830f7ea 0x338f588d 0xcee47d83
                             0x6e379438 0x2ffd710a 0xf7919f09 0xffb7c371]]
   [CAST6CFBX923     phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0x511f1f9b 0xf830f7ea 0x338f588d 0xcee47d83
                             0x6e379438 0x2ffd710a 0xf7919f09 0xffb7c375]]
   [CAST6CFBISO7816  phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0x511f1f9b 0xf830f7ea 0x338f588d 0xcee47d83
                             0x6e379438 0x2ffd710a 0xf7919f09 0x7fb7c371]]
   [CAST6OFBPKCS7    phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0xf10d2790 0xd792895a 0xdb36b0b3 0xfcfb45dd
                             0xe8b19cf1 0x1526c200 0x01704bde 0x106437ef]]
   [CAST6OFBZERO     phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0xf10d2790 0xd792895a 0xdb36b0b3 0xfcfb45dd
                             0xe8b19cf1 0x1526c200 0x01704bde 0x146033eb]]
   [CAST6OFBX923     phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0xf10d2790 0xd792895a 0xdb36b0b3 0xfcfb45dd
                             0xe8b19cf1 0x1526c200 0x01704bde 0x146033ef]]
   [CAST6OFBISO7816  phrase [0x52201908 0x40cc0eaf 0x251f7d82 0xbec73aa4
                             0xf10d2790 0xd792895a 0xdb36b0b3 0xfcfb45dd
                             0xe8b19cf1 0x1526c200 0x01704bde 0x946033eb]]])

;; ### encryptor
;; Helper function for testing encryption
(defn- encryptor [[suite pt ct] & {:keys [key iv] :or {key key-128 iv iv-128}}]
  (is (= ct (cs/encrypt suite key iv (.getBytes pt "UTF-8")))))

;; ### decryptor
;; Helper function for testing decryption
(defn- decryptor [[suite pt ct] & {:keys [key iv] :or {key key-128 iv iv-128}}]
  (is (= pt (String. (cs/decrypt suite key iv ct) "UTF-8"))))

;; ### testSuites
;; Test the various cipher suites.
(deftest testSuites
  (testing "AES"
    (is (= true (every? true? (map #(encryptor %) aes-test-vectors))))
    (is (= true (every? true? (map #(decryptor %) aes-test-vectors)))))
  (testing "Blowfish"
    (is (= true (every? true? (map #(encryptor %) bf-test-vectors))))
    (is (= true (every? true? (map #(decryptor %) bf-test-vectors)))))
  (testing "CAST5"
    (is (= true (every? true? (map #(encryptor %1 :key key-128b) cast5-test-vectors))))
    (is (= true (every? true? (map #(decryptor %1 :key key-128b) cast5-test-vectors)))))
  (testing "CAST6"
    (is (= true (every? true? (map #(encryptor %1 :key key-128b) cast6-test-vectors))))
    (is (= true (every? true? (map #(decryptor %1 :key key-128b) cast6-test-vectors))))))
