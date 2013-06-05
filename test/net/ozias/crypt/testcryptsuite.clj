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
                             [cryptsuite :refer (->AESCFB)]
                             [cryptsuite :refer (->AESOFB)]
                             [cryptsuite :refer (->AESCTR)]
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
                             [cryptsuite :refer (->BFCFB)]
                             [cryptsuite :refer (->BFOFB)]
                             [cryptsuite :refer (->BFCTR)]
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
                             [cryptsuite :refer (->CAST5CFB)]
                             [cryptsuite :refer (->CAST5OFB)]
                             [cryptsuite :refer (->CAST5CTR)]
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
                             [cryptsuite :refer (->CAST6CFB)]
                             [cryptsuite :refer (->CAST6OFB)]
                             [cryptsuite :refer (->CAST6CTR)]
                             [cryptsuite :refer (->TFECBPKCS7)]
                             [cryptsuite :refer (->TFECBZERO)]
                             [cryptsuite :refer (->TFECBISO10126)]
                             [cryptsuite :refer (->TFECBX923)]
                             [cryptsuite :refer (->TFECBISO7816)]
                             [cryptsuite :refer (->TFCBCPKCS7)]
                             [cryptsuite :refer (->TFCBCZERO)]
                             [cryptsuite :refer (->TFCBCISO10126)]
                             [cryptsuite :refer (->TFCBCX923)]
                             [cryptsuite :refer (->TFCBCISO7816)]
                             [cryptsuite :refer (->TFPCBCPKCS7)]
                             [cryptsuite :refer (->TFPCBCZERO)]
                             [cryptsuite :refer (->TFPCBCISO10126)]
                             [cryptsuite :refer (->TFPCBCX923)]
                             [cryptsuite :refer (->TFPCBCISO7816)]
                             [cryptsuite :refer (->TFCFB)]
                             [cryptsuite :refer (->TFOFB)]
                             [cryptsuite :refer (->TFCTR)]
                             [cryptsuite :refer (->S20CFB)]
                             [cryptsuite :refer (->S20OFB)]
                             [cryptsuite :refer (->S20CTR)])
            (net.ozias.crypt [testivs :refer (iv-128 iv-128b iv-64b)]
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
(def AESCFB (->AESCFB))
(def AESOFB (->AESOFB))
(def AESCTR (->AESCTR))

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
(def BFCFB (->BFCFB))
(def BFOFB (->BFOFB))
(def BFCTR (->BFCTR))

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
(def CAST5CFB (->CAST5CFB))
(def CAST5OFB (->CAST5OFB))
(def CAST5CTR (->CAST5CTR))

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
(def CAST6CFB (->CAST6CFB))
(def CAST6OFB (->CAST6OFB))
(def CAST6CTR (->CAST6CTR))

;; #### TFXX
;; Setup the Twofish suites for use in testing.
(def TFECBPKCS7 (->TFECBPKCS7))
(def TFECBZERO (->TFECBZERO))
(def TFECBISO10126 (->TFECBISO10126))
(def TFECBX923 (->TFECBX923))
(def TFECBISO7816 (->TFECBISO7816))
(def TFCBCPKCS7 (->TFCBCPKCS7))
(def TFCBCZERO (->TFCBCZERO))
(def TFCBCISO10126 (->TFCBCISO10126))
(def TFCBCX923 (->TFCBCX923))
(def TFCBCISO7816 (->TFCBCISO7816))
(def TFPCBCPKCS7 (->TFPCBCPKCS7))
(def TFPCBCZERO (->TFPCBCZERO))
(def TFPCBCISO10126 (->TFPCBCISO10126))
(def TFPCBCX923 (->TFPCBCX923))
(def TFPCBCISO7816 (->TFPCBCISO7816))
(def TFCFB (->TFCFB))
(def TFOFB (->TFOFB))
(def TFCTR (->TFCTR))

;; #### S20X
;; Setup the Salsa20 suites for use in testing.
(def S20CFB (->S20CFB))
(def S20OFB (->S20OFB))
(def S20CTR (->S20CTR))

;; #### phrase
;; A phrase to test encryption/decryption
(def phrase "The quick brown fox jumps over the lazy dog.")

;; #### aes-test-vectors
;; Test vectors for each supported AES suite
(def aes-test-vectors
  [
   ;[AESECBPKCS7    phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3 
   ;                        0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
   ;                        0xe209d7a1 0x8ed8ce63 0xf8675723 0xfa5ad724]]
   ;[AESECBZERO     phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3
   ;                        0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
   ;                        0x7ddec538 0xe17e374a 0x508b2017 0x049c3da2]]
   ;[AESECBX923     phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3
   ;                        0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
   ;                        0x02d49cad 0xc52018ff 0x0b05bea9 0x9d784d60]]
   ;[AESECBISO7816  phrase [0xf7021c01 0xde43c814 0x7cd2477a 0x7eba55b3
   ;                        0x698dc29f 0x6db0d5ed 0xa4eec682 0xb3393abb
   ;                        0xba27b732 0xc37be65e 0xd25d5757 0x1c012345]]
   ;[AESCBCPKCS7    phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
   ;                        0xff946ab7 0xaab76b32 0x37aeea72 0x9f1dd4e6]]
   ;[AESCBCZERO     phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
   ;                        0x4d9e0980 0x771d7593 0x760a7388 0xfdf7230f]]
   ;[AESCBCX923     phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
   ;                        0xfc80314b 0xcb3b582 0xd806fce8 0xb9ad034e]]
   ;[AESCBCISO7816  phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
   ;                        0x5b19892e 0x23e65691 0x2eea077b 0x6a68e32c]]
   ;[AESPCBCPKCS7   phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0x8d8ed276 0xb6970681 0x95830e5f 0x468add9f
   ;                        0x08397b9d 0xb6d327f8 0x8551a7e5 0xb8de5be]]
   ;[AESPCBCZERO    phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0x8d8ed276 0xb6970681 0x95830e5f 0x468add9f
   ;                        0xf8a5393a 0x6c0cfb7c 0xd52f5b2c 0xb9596671]]
   ;[AESPCBCX923    phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0xa2112afa 0xf1970696 0xd85445e1 0xff6817db
   ;                        0xfc80314b 0xcb3b582 0xd806fce8 0xb9ad034e]]
   ;[AESPCBCISO7816 phrase [0x6f40de04 0xce96f342 0x6280fc4c 0x87d9209a
   ;                        0x8d8ed276 0xb6970681 0x95830e5f 0x468add9f
   ;                        0x6d546556 0xcf704c73 0xa81672e7 0x63a686a6]]
;;   [AESCFB         phrase []]
;;   [AESOFB         phrase []]
;;   [AESCTR         phrase []]
])

;; #### bf-test-vectors
;; Test vectors for each supported Blowfish suite
(def bf-test-vectors
  [;[BFECBPKCS7    phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
   ;                       0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
   ;                       0x0d9c9da2 0x58b94843 0x12ddbdf0 0x75fe5aaa]]
   ;[BFECBZERO     phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
   ;                       0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
   ;                       0x0d9c9da2 0x58b94843 0x8e2a98a9 0xd6cda8c9]]
   ;[BFECBX923     phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
   ;                      0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
   ;                       0x0d9c9da2 0x58b94843 0xa4fdbf45 0x7a9ef177]]
   ;[BFECBISO7816  phrase [0xacf3f188 0xc68cd2d4 0x599b78c9 0xba105bef
   ;                       0x1e57ce93 0x1d441386 0x23959354 0xc70901ec
   ;                       0x0d9c9da2 0x58b94843 0x2a619282 0xd291a306]]
   ;[BFCBCPKCS7    phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f 
   ;                       0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6 
   ;                       0x55c680fe 0xabaae236 0x36ff9ff8 0xcf85485f]]
   ;[BFCBCZERO     phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f
   ;                       0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6
   ;                       0x55c680fe 0xabaae236 0x795fdd05 0xda068fa1]]
   ;[BFCBCX923     phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f
   ;                       0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6
   ;                       0x55c680fe 0xabaae236 0xde262374 0xae26f17f]]
   ;[BFCBCISO7816  phrase [0xbdf91633 0xc1068045 0x4ae7d456 0xeccbc94f
   ;                      0xcee6b9ea 0xbf248754 0xb922030a 0xe72d5db6
   ;                       0x55c680fe 0xabaae236 0x16b373c6 0xf532798e]]
   ;[BFPCBCPKCS7   phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
   ;                       0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
   ;                       0x6c52a2ba 0x7dbcbf67 0x2b85eb8e 0xe8ab37ee]]
   ;[BFPCBCZERO    phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
   ;                       0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
   ;                       0x6c52a2ba 0x7dbcbf67 0x13ea40c1 0x29c0805d]]
   ;[BFPCBCX923    phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
   ;                       0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
   ;                       0x6c52a2ba 0x7dbcbf67 0xe844a968 0x4d082c19]]
   [BFPCBCISO7816 phrase [0xbdf91633 0xc1068045 0x564caf9d 0x9795d0b1
                          0x19e5fc29 0x519accef 0x4c79fe3e 0xf44f0eba
                          0x6c52a2ba 0x7dbcbf67 0xf13abe40 0x12fa8b32]]
;;   [BFCFB         phrase []]
;;   [BFOFB         phrase []]
;;   [BFCTR         phrase []]
])

;; #### cast5-test-vectors
;; Test vectors for each supported CAST5 suite
(def cast5-test-vectors
  [;[CAST5ECBPKCS7    phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
   ;                          0x77222960 0x6685b5d2 0x03822655 0xfffd9170
   ;                          0x561c926f 0x8fcedd2b 0xc7fdcf2e 0x83a687bd]]
   ;[CAST5ECBZERO     phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
   ;                          0x77222960 0x6685b5d2 0x03822655 0xfffd9170
   ;                          0x561c926f 0x8fcedd2b 0xf9bcab93 0x89b48066]]
   ;[CAST5ECBX923     phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
   ;                          0x77222960 0x6685b5d2 0x03822655 0xfffd9170
   ;                          0x561c926f 0x8fcedd2b 0xfef0bd65 0xb791c4a0]]
   ;[CAST5ECBISO7816  phrase [0x34e1b3fc 0x0d72f1d8 0x5d837126 0x6e69cc65
   ;                          0x77222960 0x6685b5d2 0x03822655 0xfffd9170
   ;                          0x561c926f 0x8fcedd2b 0x078ec9bd 0x3afea3b1]]
   ;[CAST5CBCPKCS7    phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
   ;                          0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
   ;                          0xfb5f3523 0x9aea1a6a 0xf32df9da 0xd8a447e8]]
   ;[CAST5CBCZERO     phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
   ;                          0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
   ;                          0xfb5f3523 0x9aea1a6a 0x900111ee 0x532e7629]]
   ;[CAST5CBCX923     phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
   ;                          0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
   ;                          0xfb5f3523 0x9aea1a6a 0xf298698c 0x66a12e1e]]
   ;[CAST5CBCISO7816  phrase [0x7bfb801a 0x5c6e9c36 0xc9282d18 0x5069149b
   ;                          0x8f1cd593 0xbc84d9f9 0x29bf9de9 0x3c07f9a3
   ;                          0xfb5f3523 0x9aea1a6a 0x3013af87 0x261bea0a]]
   ;[CAST5PCBCPKCS7   phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
   ;                          0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
   ;                          0x1fc7865d 0x0ca1371b 0x023404ed 0xead34e2a]]
   ;[CAST5PCBCZERO    phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
   ;                          0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
   ;                          0x1fc7865d 0x0ca1371b 0xcb2d2cf9 0x21ec8f86]]
   ;[CAST5PCBCX923    phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
   ;                          0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
   ;                          0x1fc7865d 0x0ca1371b 0x6ccb25fa 0x9853500b]]
   ;[CAST5PCBCISO7816 phrase [0x7bfb801a 0x5c6e9c36 0x6952d07b 0x4877feb3
   ;                          0xe62349f8 0xbdfb4b21 0x0fe7c58d 0x5f6c3049
   ;                          0x1fc7865d 0x0ca1371b 0xdf93ffe8 0x5a976927]]
;;   [CAST5CFB         phrase []]
;;   [CAST5OFB         phrase []]
;;   [CAST5CTR         phrase []]
])

;; #### cast6-test-vectors
;; Test vectors for each supported CAST6 suite
(def cast6-test-vectors
  [;[CAST6ECBPKCS7    phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
   ;                          0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
   ;                          0xed9cf548 0x55edc7c6 0x56a94528 0xef50218f]]
   ;[CAST6ECBZERO     phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
   ;                          0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
   ;                          0x40c1394f 0x20956d67 0x012e820f 0x75a6b853]]
   ;[CAST6ECBX923     phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
   ;                          0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
   ;                          0xac17f63a 0xe8c185d2 0x909a8f2d 0x77fbbe9c]]
   ;[CAST6ECBISO7816  phrase [0x16a8f433 0x3954ed44 0xe2991485 0x5fc31a07
   ;                          0xedda7098 0x6a877194 0x0fb47b6c 0xfa1d087e
   ;                          0xfd1b3087 0xfdc4d6c9 0xc3f301da 0xb181adfb]]
   ;[CAST6CBCPKCS7    phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0x633c745e 0x1940d579 0xf57bea1c 0x39486330
   ;                          0xc59fe2d2 0x6b0b12de 0xf478a36f 0x7cd7c3bc]]
   ;[CAST6CBCZERO     phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0x633c745e 0x1940d579 0xf57bea1c 0x39486330
   ;                          0xf59481a7 0x223b82c5 0x9fbee450 0x49a969cb]]
   ;[CAST6CBCX923     phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0x633c745e 0x1940d579 0xf57bea1c 0x39486330
   ;                          0x80e0c88f 0x2af0abf0 0x5b960339 0x632d8b92]]
   ;[CAST6CBCISO7816  phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0x633c745e 0x1940d579 0xf57bea1c 0x39486330
   ;                          0x7fa8f65e 0x10507d61 0x38a88894 0x696b5763]]
   ;[CAST6PCBCPKCS7   phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
   ;                          0xf826cd2d 0x972ff4e4 0x3d32ff00 0x87ef0a7a]]
   ;[CAST6PCBCZERO    phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
   ;                          0xcddd45e2 0xc924c710 0x9881fe79 0xa2ccf011]]
   ;[CAST6PCBCX923    phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
   ;                          0x4824ce3a 0x98bafc05 0xd5db54d4 0x76b6512c]]
   ;[CAST6PCBCISO7816 phrase [0x1df5aff3 0xf5b0a7cf 0x037de8da 0xfb6fad9f
   ;                          0xcc4ab7e2 0x8e425de0 0x5d1688e4 0xe1d24403
   ;                          0x8a91d9d0 0x0b6c3527 0x02876a9c 0x00ee1032]]
;;   [CAST6CFB         phrase []]
;;   [CAST6OFB         phrase []]
;;   [CAST6CTR         phrase []]
])

;; #### tf-test-vectors
;; Test vectors for each supported Twofish suite
(def tf-test-vectors
  [[TFECBPKCS7    phrase [0x62 0xD6 0x24 0x29 0x1F 0x51 0xD8 0xD4
                          0x18 0x40 0x96 0x09 0x8F 0xB4 0x06 0xAE
                          0xDD 0x7B 0x55 0x4C 0x93 0x54 0xAE 0x8C
                          0xA7 0xD6 0x21 0xCD 0x03 0xFC 0xB2 0x1B
                          0xE4 0xD6 0xBF 0x1B 0x8C 0x8E 0xE7 0x24
                          0x77 0xE5 0xA9 0xD6 0x57 0xBF 0x7E 0x36]]
   ;[TFECBZERO     phrase [0x8CC4BDF2 0x3238AA72 0xC414702B 0xF1E746CA
   ;                       0x0AA44ECC 0x965706D3 0x02A36C85 0x2F12DED3
   ;                       0xB0282B3F 0x97533E3F 0x2B486704 0x6288AD7C]]
   ;[TFECBX923     phrase [0x8CC4BDF2 0x3238AA72 0xC414702B 0xF1E746CA
   ;                       0x0AA44ECC 0x965706D3 0x02A36C85 0x2F12DED3
   ;                       0x9CF28E99 0x115A9C6D 0x2FD20232 0x6CDD9DAB]]
   ;[TFECBISO7816  phrase [0x8CC4BDF2 0x3238AA72 0xC414702B 0xF1E746CA
   ;                       0x0AA44ECC 0x965706D3 0x02A36C85 0x2F12DED3
   ;                       0xC39BDDB4 0x8F2A7838 0x854152A9 0x37BE3A64]]
   ;[TFCBCPKCS7    phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0xB6B6AF4D 0xA8E49CD1 0xAF413D94 0xD58A4209
   ;                       0x00B243DF 0x57C1186D 0x1B6AF535 0x495E488E]]
   ;[TFCBCZERO     phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0xB6B6AF4D 0xA8E49CD1 0xAF413D94 0xD58A4209
   ;                       0x1032CC97 0x73D10AD2 0x87E65230 0xFCE7BF95]]
   ;[TFCBCX923     phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0xB6B6AF4D 0xA8E49CD1 0xAF413D94 0xD58A4209
   ;                       0x7F180009 0x86547F24 0xC25317F2 0x8E04EBD6]]
   ;[TFCBCISO7816  phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0xB6B6AF4D 0xA8E49CD1 0xAF413D94 0xD58A4209
   ;                       0xB3F9229C 0xBB37B7D3 0x2D0292AD 0x5C49EF22]]
   ;[TFPCBCPKCS7   phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0x20E95A38 0xE401C7E7 0x23E630EB 0x67038354
   ;                       0x7AB5318B 0x3A68614F 0x7D47E004 0x8501A27E]]
   ;[TFPCBCZERO    phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0x20E95A38 0xE401C7E7 0x23E630EB 0x67038354
   ;                       0xC9CBF9D9 0x55148687 0x5BA04DA9 0x2A5412F0]]
   ;[TFPCBCX923    phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0x20E95A38 0xE401C7E7 0x23E630EB 0x67038354
   ;                       0xEB172D7C 0x191BBCF2 0x75940A4C 0x8B85CB16]]
   ;[TFPCBCISO7816 phrase [0xC82A136C 0x5909486E 0x8441FDDD 0xC117459E
   ;                       0x20E95A38 0xE401C7E7 0x23E630EB 0x67038354
   ;                       0x3D9A63D1 0x75B06C26 0x278FF5E1 0xF97E7D05]]
])

;; #### tfs-test-vectors
;; Test vectors for Twofish (Stream)
(def tfs-test-vectors
  [[TFCFB phrase [0x8F 0x25 0x51 0xEB 0x35 0x08 0x26 0x7E 0x68
                  0x81 0x50 0x27 0x2E 0x21 0x4C 0xB6 0x3D 0x89
                  0xC0 0x5A 0x28 0xD8 0xFB 0x57 0x2E 0x9F 0x72
                  0x03 0x0E 0xED 0x0B 0x6F 0x9C 0x2B 0x78 0x84
                  0x36 0xBA 0xE4 0xDD 0xFD 0x97 0xF3 0x6C]]
   [TFOFB phrase [0x8F 0x51 0x45 0xDF 0x67 0x07 0xD2 0xCE 0xD4
                  0xCB 0x7D 0x57 0xFF 0x71 0x62 0x0B 0xB5 0xA3
                  0x79 0x17 0xEB 0xFE 0xE9 0x99 0x13 0x99 0x30
                  0x15 0x62 0x61 0xAC 0x21 0xEF 0x8B 0x30 0xE3
                  0x50 0x59 0xA7 0xD2 0x52 0xA5 0xEB 0x54]]])

;; #### tfctr-test-vectors
;; Test vectors for the Twofish suite, Counter mode
(def tfctr-test-vectors
  [[TFCTR phrase [0xA3 0xAA 0xDE 0x29 0xC2 0x7A 0x2A 0xEB 0x50
                  0x3F 0xF2 0xC2 0x1D 0x40 0xFA 0xFE 0xAB 0x7D
                  0x59 0xC3 0x87 0x5D 0x9C 0x86 0x61 0x29 0xDF
                  0x4F 0xF8 0x48 0xBC 0xEE 0x55 0x3A 0x62 0x44
                  0x8B 0x2E 0xCF 0x7B 0xDE 0xAC 0xFE 0xBF]]])

;; #### s20s-test-vectors
;; Test vectors for Salsa20 (Stream)
(def s20s-test-vectors
  [[S20CFB phrase [0xDD 0xC8 0xD4 0xCC 0x9E 0x0D 0x46 0x37 0x14
                   0xEE 0xC4 0x9E 0xB1 0x24 0x07 0x75 0xB8 0x12
                   0xF2 0x66 0x79 0x90 0xBA 0xE6 0x30 0x26 0x83
                   0x59 0x0F 0x46 0x03 0xE8 0x4D 0x7F 0x80 0x74
                   0x23 0x0B 0x5A 0x8E 0xFB 0xA5 0x26 0xFB]]
   [S20OFB phrase [0xDD 0x72 0x6A 0xDD 0x26 0x6D 0x64 0xA9 0x36
                   0xD0 0x5B 0xFE 0x01 0xE1 0x85 0xCF 0xD8 0x50
                   0x15 0xB5 0x86 0x81 0x44 0xAB 0x80 0x57 0x5B
                   0x58 0x16 0x99 0xED 0x01 0x42 0x93 0xBE 0x6C
                   0x06 0x2D 0xEF 0x11 0x51 0xC8 0xE9 0x99]]])

;; #### s20ctr-test-vectors
;; Test vectors for the Salsa20 suite, Counter mode
(def s20ctr-test-vectors
  [[S20CTR phrase [0x6D 0x5E 0xE6 0x3D 0x2B 0xE3 0x3D 0x3D 0x84
                   0x46 0xB1 0xBD 0xFF 0xCF 0x02 0xB2 0x9E 0x1A
                   0x57 0x2C 0x93 0x34 0x76 0x20 0x47 0xBC 0x66
                   0xE4 0x2B 0x50 0xC9 0x86 0xCF 0xFB 0x69 0x28
                   0x3A 0x1A 0x44 0x47 0xC6 0xBC 0x2C 0x64]]])

;; #### array-of-bytes-type
;; Used in byte-array? for comparison
(def array-of-bytes-type (Class/forName "[B")) 

;; ### byte-array?
;; Is the given object a byte-array (type [B)
(defn- byte-array? [obj]
  (= (type obj) array-of-bytes-type))

;; ### to-bytearray
;; Convert the given vector of bytes to a [B
;; if it is not already converted.
;;
;; Evaluates to a [B over the given byte vector
(defn- to-bytearray [bytes]
  (if (not (byte-array? bytes))
    (byte-array (mapv byte bytes))
    bytes))

;; ### encryptor
;; Helper function for testing encryption
(defn- encryptor [[suite pt ct] & {:keys [key iv] :or {key key-128 iv iv-128}}]
  (is (= ct (cs/encrypt suite key iv (vec (.getBytes pt "UTF-8"))))))

;; ### decryptor
;; Helper function for testing decryption
(defn- decryptor [[suite pt ct] & {:keys [key iv] :or {key key-128 iv iv-128}}]
  (is (= pt (String. (to-bytearray (cs/decrypt suite key iv ct)) "UTF-8"))))

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
    (is (= true (every? true? (map #(decryptor %1 :key key-128b) cast6-test-vectors)))))
  (testing "Twofish"
    (is (= true (every? true? (map #(encryptor % :key key-128b) tf-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :key key-128b) tf-test-vectors)))))
  (testing "Twofish (Stream)"
    (is (= true (every? true? (map #(encryptor % :key key-128b :iv iv-128b) tfs-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :key key-128b :iv iv-128b) tfs-test-vectors)))))
  (testing "Twofish (CTR)"
    (is (= true (every? true? (map #(encryptor % :key key-128b :iv iv-64b) tfctr-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :key key-128b :iv iv-64b) tfctr-test-vectors)))))
  (testing "Salsa20 (Stream)"
    (is (= true (every? true? (map #(encryptor % :key key-128b :iv iv-128b) s20s-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :key key-128b :iv iv-128b) s20s-test-vectors)))))
  (testing "Salsa20 (CTR)"
    (is (= true (every? true? (map #(encryptor % :key key-128b :iv iv-64b) s20ctr-test-vectors))))
    (is (= true (every? true? (map #(decryptor % :key key-128b :iv iv-64b) s20ctr-test-vectors))))))
