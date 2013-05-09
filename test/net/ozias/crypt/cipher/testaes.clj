;; ## Test AES Encryption Engine
(ns ^{:author "Jason Ozias"}
     net.ozias.crypt.cipher.testaes
     (:require [net.ozias.crypt.cipher.aes :refer (->Aes)]
               [net.ozias.crypt.cipher.blockcipher :as bc]))

(def test-state
  (vector 0x00112233
          0x44556677
          0x8899aabb
          0xccddeeff))

(def test-decrypt-state-128
  (vector 0x69c4e0d8
          0x6a7b0430 
          0xd8cdb780
          0x70b4c55a))

(def test-decrypt-state-192
  (vector 0xdda97ca4
          0x864cdfe0
          0x6eaf70a0
          0xec0d7191))

(def test-decrypt-state-256
  (vector 0x8ea2b7ca
          0x516745bf
          0xeafc4990 
          0x4b496089))

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

(def test-key-256 
  (vector 0x00010203
          0x04050607
          0x08090a0b
          0x0c0d0e0f
          0x10111213
          0x14151617
          0x18191a1b
          0x1c1d1e1f))

(def aes (->Aes))

(defn test-blocksize []
  (bc/blocksize aes))

(defn test-encrypt-block [state key]
  (mapv #(Long/toHexString %) (bc/encrypt-block aes state key)))

(defn test-128-encrypt-block []
  (test-encrypt-block test-state test-key-128))

(defn test-192-encrypt-block []
  (test-encrypt-block test-state test-key-192))

(defn test-256-encrypt-block []
  (test-encrypt-block test-state test-key-256))

(defn test-all-encrypt-block []
  (map #(test-encrypt-block test-state %) 
       (vector test-key-128 test-key-192 test-key-256)))

(defn test-decrypt-block [state key]
  (mapv #(Long/toHexString %) (bc/decrypt-block aes state key)))

(defn test-128-decrypt-block []
  (test-decrypt-block test-decrypt-state-128 test-key-128))

(defn test-192-decrypt-block []
  (test-decrypt-block test-decrypt-state-192 test-key-192))

(defn test-256-decrypt-block []
  (test-decrypt-block test-decrypt-state-256 test-key-256))

(defn test-all-decrypt-block []
  (map #(test-decrypt-block %1 %2) 
       (vector test-decrypt-state-128
               test-decrypt-state-192
               test-decrypt-state-256)
       (vector test-key-128
               test-key-192
               test-key-256)))

(defn encrypt-decrypt [key]
  (fn []
    (mapv #(Long/toHexString %) 
          (bc/decrypt-block aes (bc/encrypt-block aes test-state key) key))))

(defn test-128-both []
  ((encrypt-decrypt test-key-128)))

(defn test-192-both []
  ((encrypt-decrypt test-key-192)))

(defn test-256-both []
  ((encrypt-decrypt test-key-256)))
