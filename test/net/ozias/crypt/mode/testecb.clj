;; # Test Electronic Codebook Mode
;; Test suite for the ECB mode of encrypting multiple blocks.
(ns net.ozias.crypt.mode.testecb
  (:require [clojure.test :refer :all]
            [net.ozias.crypt.mode.ecb :refer (->ElectronicCodebook)]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blockcipher :as bc]
            [net.ozias.crypt.mode.modeofoperation :as mode]
            [net.ozias.crypt.testkeys :refer (key-128)]))

;; ### pt-msg
;; A sample plaintext message.  In this case it is my name as 11 
;; UTF-8 bytes (0x4a61736f63204f7a696173) repeated 16 times to make 11 blocks.
(def pt-msg
  [0x4a61736f 0x6e204f7a 0x6961734a 0x61736f6e
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
  [0xf98bbfbd 0x761385a0 0x8301b617 0x2eac2a18 
   0xfa3e70a2 0x6c1bae31 0x04e44e83 0x4d3d20ee
   0x60912070 0xd4a26755 0x24d945b5 0xb550b9e3
   0x372cf4ac 0x4e33d4c2 0x69663f71 0x2c24931f
   0x2d4fa5d8 0x2bac8b7f 0x477d6ed0 0x92fa8677
   0x9c6b0b32 0xb46a1782 0x35b8afa4 0xa2bfe9e9
   0xb6646b63 0x00230106 0x0dcd1d38 0x93ffac22
   0xc9aa4d89 0xef55b01a 0xfa161a19 0xf54505b8
   0x9050c766 0x096cb2dd 0x3342266b 0xfa145275
   0x8b3c2e4b 0x482e5269 0x0d9ddcab 0xcb4dda28
   0x255cd45d 0x39280648 0x63d58448 0x24738d49])

;; ### ECB
;; Setup the ElectronicCodebook record for use in tests
(def ECB (->ElectronicCodebook))
;; ### AES
;; Setup the Aes record for use in tests
(def AES (->Aes))

;; ## encrypt-blocks
;; Encrypt a vector of blocks with ECB and the given cipher, and key.
(defn- encrypt-blocks [cipher blocks key]
  (mode/encrypt-blocks ECB cipher nil blocks key))

;; ## decrypt-blocks
;; Decrypt a vector of blocks with CBC and the given cipher, iv, and key.
(defn- decrypt-blocks [cipher blocks key]
  (mode/decrypt-blocks ECB cipher nil blocks key))

;; ## testECB
;; Test the Electronic Codebook mode
(deftest testECB
  (testing "Encryption"
    (testing "AES"
      (is (= ct-128-msg (encrypt-blocks AES pt-msg key-128)))))
  (testing "Decryption"
    (testing "AES"
      (is (= pt-msg (decrypt-blocks AES ct-128-msg key-128))))))
