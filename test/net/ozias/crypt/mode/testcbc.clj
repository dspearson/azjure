(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.testcbc
  (:require [net.ozias.crypt.mode.cbc :refer (->CipherBlockChaining)]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.twofish :refer (->Twofish)]
            [net.ozias.crypt.cipher.blockcipher :as bc]
            [net.ozias.crypt.mode.modeofoperation :as mode]))

;; My name as UTF-8 (11 bytes)
;; repeated 16 times to make 11 blocks
(def test-msg
  (vector 0x4a61736f 0x6e204f7a 0x6961734a 0x61736f6e
          0x204f7a69 0x61734a61 0x736f6e20 0x4f7a6961
          0x734a6173 0x6f6e204f 0x7a696173 0x4a61736f
          0x6e204f7a 0x6961734a 0x61736f6e 0x204f7a69
          0x61734a61 0x736f6e20 0x4f7a6961 0x734a6173
          0x6f6e204f 0x7a696173 0x4a61736f 0x6e204f7a
          0x6961734a 0x61736f6e 0x204f7a69 0x61734a61
          0x736f6e20 0x4f7a6961 0x734a6173 0x6f6e204f
          0x7a696173 0x4a61736f 0x6e204f7a 0x6961734a
          0x61736f6e 0x204f7a69 0x61734a61 0x736f6e20
          0x4f7a6961 0x734a6173 0x6f6e204f 0x7a696173))

(def test-decrypt-msg-128
  (vector 0x87a3f4f9 0x51c2e601 0x8295e40d 0xb6278619
          0x096026c7 0x72e928ba 0x085997d2 0xd05fe365
          0x9c907d01 0x6f61d49e 0x7146b7e0 0x4bb810ef
          0x3429eb6c 0x02605a21 0xdd9d7a7c 0x25b69cab
          0x8161e6e2 0x7fc614bf 0x8cf8051c 0xd816260c
          0xec9ecdb7 0xe6a7fb4d 0x1236fffc 0xbfe3903b
          0x8bcd6bee 0x214cde58 0x1cb172bb 0xcd9b721d
          0x461b3e07 0xb15178ec 0x141617c6 0x5b6cf605
          0x40692fa0 0x36ebef5f 0x6fe253be 0x89be47a0
          0xa8876b85 0x94b7478b 0x557040d7 0x0dc65e85
          0xff272147 0x6d19cddd 0x1b475267 0xc937a77e))

(def test-key-128 
  (vector 0x00010203
          0x04050607
          0x08090a0b
          0x0c0d0e0f))

(def test-key-192
  (vector 0x00010203
          0x04050607
          0x08090a0b
          0x0c0d0e0f
          0x10111213
          0x14151617))

(def test-iv
  (vector 0x0f0e0d0c
          0x0b0a0908
          0x07060504
          0x03020100))

(defn test-encrypt-blocks []
  (mapv #(Long/toHexString %) 
        (mode/encrypt-blocks (->CipherBlockChaining) (->Aes) test-iv test-msg test-key-128)))

(defn test-decrypt-blocks []
  (mapv #(Long/toHexString %)
        (mode/decrypt-blocks (->CipherBlockChaining) (->Aes) test-iv test-decrypt-msg-128 test-key-128)))
