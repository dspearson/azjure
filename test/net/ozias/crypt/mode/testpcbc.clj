;; # Test Propagating Cipher Block Chaining Mode
;; Test suite for the PCBC mode of encrypting multiple blocks.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.testpcbc
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.testkeys :refer :all]
            [net.ozias.crypt.testivs :refer :all]
            [net.ozias.crypt.mode.pcbc :refer (->PropagatingCipherBlockChaining)]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
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

(def aes-ct-128-msg
  [0x87a3f4f9 0x51c2e601 0x8295e40d 0xb6278619
   0xa96fe084 0xdfb070f3 0x86743988 0xfe60f12a
   0x68cc4a82 0xafd90f5f 0x0066f23f 0x0188263a 
   0x3dfc721f 0xa8157f0b 0xdd1bad97 0x0e358781
   0x0dfc9fd4 0xc8810ddb 0x23ea394a 0x7d25960b
   0x85d1c1e6 0xe36f0485 0x8d32c4b1 0x0ea0d61e
   0xfb24d4ef 0x10276c98 0x257138ef 0x0fc57833
   0xc0f37794 0x6bbb36f4 0xd46ef1ff 0x2b9c2465
   0xd205495e 0xac14eaa3 0x2e5efab7 0x0c102d4e
   0x37cbc0d7 0x436c9838 0x1a1c1077 0xbb5bbcc3
   0x3a30e4a0 0x634b02e9 0x1e9c1ce0 0xfc848eef])

;; ### PCBC
;; Setup the PropagatingCipherBlockChaining record for use in tests
(def PCBC (->PropagatingCipherBlockChaining))
;; ### AES
;; Setup the Aes record for use in tests
(def AES (->Aes))
;; ### Blowfish
;; Setup the Blowfish record for use in tests
(def Blowfish (->Blowfish))

;; ## encrypt-blocks
;; Encrypt a vector of blocks with CBC and the given cipher, iv, and key.
(defn- encrypt-blocks [cipher iv blocks key]
  (mode/encrypt-blocks PCBC cipher iv blocks key))

;; ## decrypt-blocks
;; Decrypt a vector of blocks with CBC and the given cipher, iv, and key.
(defn- decrypt-blocks [cipher iv blocks key]
  (mode/decrypt-blocks PCBC cipher iv blocks key))

;; ## testPCBC
;; Test the Propagating Chaining Block Cipher mode
(deftest testCBC
  (testing "Encryption"
    (testing "AES"
      (testing "IV, 128-bit Key"
        (is (= aes-ct-128-msg (encrypt-blocks AES iv-128 pt-msg key-128)))))))
