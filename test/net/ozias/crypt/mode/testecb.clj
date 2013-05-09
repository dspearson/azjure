(ns net.ozias.crypt.mode.testecb
  (:require [net.ozias.crypt.mode.ecb :refer (->ElectronicCodebook)]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
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
  (vector 0xf98bbfbd 0x761385a0 0x8301b617 0x2eac2a18 
          0xfa3e70a2 0x6c1bae31 0x04e44e83 0x4d3d20ee
          0x60912070 0xd4a26755 0x24d945b5 0xb550b9e3
          0x372cf4ac 0x4e33d4c2 0x69663f71 0x2c24931f
          0x2d4fa5d8 0x2bac8b7f 0x477d6ed0 0x92fa8677
          0x9c6b0b32 0xb46a1782 0x35b8afa4 0xa2bfe9e9
          0xb6646b63 0x00230106 0x0dcd1d38 0x93ffac22
          0xc9aa4d89 0xef55b01a 0xfa161a19 0xf54505b8
          0x9050c766 0x096cb2dd 0x3342266b 0xfa145275
          0x8b3c2e4b 0x482e5269 0x0d9ddcab 0xcb4dda28
          0x255cd45d 0x39280648 0x63d58448 0x24738d49))

(def test-key-128 
  (vector 0x00010203
          0x04050607
          0x08090a0b
          0x0c0d0e0f))

(defn test-encrypt-blocks []
  (mapv #(Long/toHexString %) 
        (mode/encrypt-blocks (->ElectronicCodebook) (->Aes) nil test-msg test-key-128)))

(defn test-decrypt-blocks []
  (mapv #(Long/toHexString %)
        (mode/decrypt-blocks (->ElectronicCodebook) (->Aes) nil test-decrypt-msg-128 test-key-128)))
