;; # Test Cipher Block Chaining Mode
;; Test suite for the CBC mode for encrypting multiple blocks.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.testcbc
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.testkeys :refer :all]
            [net.ozias.crypt.testivs :refer :all]
            [net.ozias.crypt.mode.cbc :refer (->CipherBlockChaining)]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.twofish :refer (->Twofish)]
            [net.ozias.crypt.cipher.blockcipher :as bc]
            [net.ozias.crypt.mode.modeofoperation :as mode]))

;; ### pt-msg
;; A sample plaintext message.  In this case it is my name as 11 
;; UTF-8 bytes (0x4a61736f63204f7a696173) repeated 16 times to make 11 blocks.
(def pt-msg [0x4a61736f 0x6e204f7a 0x6961734a 0x61736f6e
             0x204f7a69 0x61734a61 0x736f6e20 0x4f7a6961
             0x734a6173 0x6f6e204f 0x7a696173 0x4a61736f
             0x6e204f7a 0x6961734a 0x61736f6e 0x204f7a69
             0x61734a61 0x736f6e20 0x4f7a6961 0x734a6173
             0x6f6e204f 0x7a696173 0x4a61736f 0x6e204f7a
             0x6961734a 0x61736f6e 0x204f7a69 0x61734a61
             0x736f6e20 0x4f7a6961 0x734a6173 0x6f6e204f
             0x7a696173 0x4a61736f 0x6e204f7a 0x6961734a
             0x61736f6e 0x204f7a69 0x61734a61 0x736f6e20
             0x4f7a6961 0x734a6173 0x6f6e204f 0x7a696173])

;; ### ct-128-msg
;; A sample ciphertext message that is the result of encrypting
;; <em>pt-msg</em> with AES and key-128.
(def ct-128-msg 
  [0x87a3f4f9 0x51c2e601 0x8295e40d 0xb6278619
   0x096026c7 0x72e928ba 0x085997d2 0xd05fe365
   0x9c907d01 0x6f61d49e 0x7146b7e0 0x4bb810ef
   0x3429eb6c 0x02605a21 0xdd9d7a7c 0x25b69cab
   0x8161e6e2 0x7fc614bf 0x8cf8051c 0xd816260c
   0xec9ecdb7 0xe6a7fb4d 0x1236fffc 0xbfe3903b
   0x8bcd6bee 0x214cde58 0x1cb172bb 0xcd9b721d
   0x461b3e07 0xb15178ec 0x141617c6 0x5b6cf605
   0x40692fa0 0x36ebef5f 0x6fe253be 0x89be47a0
   0xa8876b85 0x94b7478b 0x557040d7 0x0dc65e85
   0xff272147 0x6d19cddd 0x1b475267 0xc937a77e])

;; ### ct-192-msg
;; A sample ciphertext message that is the result of encrypting
;; <em>pt-msg</em> with AES and key-192.
(def ct-192-msg
  [0xb46a08a4 0x06e5c7a6 0xae63f25d 0x42453eba
   0xdec39aad 0x2295880f 0x5bb16bd4 0xa67664c5
   0xa643dba7 0x7ce9663a 0x0961fb1f 0x3ddc82a1
   0x21b39703 0xaeb4d122 0x2697f9d6 0xdec26955
   0xdbf57f73 0x170d9a0f 0x092868c6 0x5cdbf77c
   0x7bed0b13 0x7a8d917b 0xd0330034 0xa2a2fc38
   0x2691f2e0 0xa11f8712 0x2dc55534 0x992c9257
   0x65804741 0x83e01e40 0x48591a77 0xb38c36c2
   0xcea6258a 0x8b7b0332 0xa04fca42 0xef2fb5de
   0x52645170 0x957a5013 0x5d791119 0x9c3de4be
   0x7e3a5457 0x896d477f 0x588c3fd3 0xc7062114])

;; ### ct-256-msg
;; A sample ciphertext message that is the result of encrypting
;; <em>pt-msg</em> with AES and key-256.
(def ct-256-msg
  [0x2f438979 0xcb1abdbd 0x84880cfb 0x18533338
   0xb3c1cf96 0x9380453b 0x1c7cea2c 0x3cb1d78c
   0x21e0eb91 0xc962af80 0x1f6b3a4e 0x3e2df0d6
   0x4b268f0d 0x53fcb5f7 0xefbe2aef 0xfcb4bf7c
   0xc98354ac 0x98bba698 0x5e124c01 0xc461085d
   0xb3a76c21 0x4c7e6549 0x23f137fe 0x78a4b8a2
   0xf3358469 0x255aa294 0x7fd6d723 0x5cb95e74
   0x48fe8cf1 0xd86ab8b3 0x978d2ef1 0x23f0b92a
   0x7173a1a3 0xdf3e65c1 0x3c3dbb65 0x74eb58fe
   0xa3393856 0xf92fe6d5 0x5f130dbe 0x48523022
   0x872e7f79 0x2590c5aa 0x912aee70 0x195b05c2])

;; ### CBC
;; Setup the CipherBlockChaining record for use in tests
(def CBC (->CipherBlockChaining))
;; ### AES
;; Setup the Aes record for use in tests
(def AES (->Aes))
;; ### Twofish
;; Setup the Twofish record for use in tests
(def Twofish (->Twofish))

;; ## encrypt-blocks
;; Encrypt a vector of blocks with CBC and the given cipher, iv, and key.
(defn- encrypt-blocks [cipher iv blocks key]
  (mode/encrypt-blocks CBC cipher iv blocks key))

;; ## decrypt-blocks
;; Decrypt a vector of blocks with CBC and the given cipher, iv, and key.
(defn- decrypt-blocks [cipher iv blocks key]
  (mode/decrypt-blocks CBC cipher iv blocks key))

;; ## testCBC
;; Test the Chaining Block Cipher mode
(deftest testCBC
  (testing "Encryption"
    (testing "AES"
      (testing "IV, 128-bit Key"
        (is (= ct-128-msg (encrypt-blocks AES iv-128 pt-msg key-128))))
      (testing "Different IV, Same 128-bit Key"
        (is (not (= ct-128-msg (encrypt-blocks AES iv-128-1 pt-msg key-128)))))
      (testing "IV, 192-bit Key"
        (is (= ct-192-msg (encrypt-blocks AES iv-128 pt-msg key-192))))
      (testing "Different IV, Same 192-bit Key"
        (is (not (= ct-192-msg (encrypt-blocks AES iv-128-1 pt-msg key-192)))))
      (testing "IV, 256-bit Key"
        (is (= ct-256-msg (encrypt-blocks AES iv-128 pt-msg key-256))))
      (testing "Different IV, Same 256-bit Key"
        (is (not (= ct-256-msg (encrypt-blocks AES iv-128-1 pt-msg key-256))))))
    (testing "Twofish"))
  (testing "Decryption"
    (testing "AES"
      (testing "IV, 128-bit Key"
        (is (= pt-msg (decrypt-blocks AES iv-128 ct-128-msg key-128))))
      (testing "Different IV, Same 128-bit Key"
        (is (not (= pt-msg (decrypt-blocks AES iv-128-1 ct-128-msg key-128)))))
      (testing "IV, 192-bit Key"
        (is (= pt-msg (decrypt-blocks AES iv-128 ct-192-msg key-192))))
      (testing "Different IV, Same 192-bit Key"
        (is (not (= pt-msg (decrypt-blocks AES iv-128-1 ct-192-msg key-192)))))
      (testing "IV, 256-bit Key"
        (is (= pt-msg (decrypt-blocks AES iv-128 ct-256-msg key-256))))
      (testing "Different IV, Same 256-bit Key"
        (is (not (= pt-msg (decrypt-blocks AES iv-128-1 ct-256-msg key-256))))))
    (testing "Twofish")))
