;; ## Test AES Encryption Engine
(ns ^{:author "Jason Ozias"}
     com.ozias.net.crypt.testaes
     (:require 
      [com.ozias.net.crypt.aes
       :refer [encrypt-block decrypt-block]]))

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
  (vector 0x00 0x01 0x02 0x03
          0x04 0x05 0x06 0x07
          0x08 0x09 0x0a 0x0b
          0x0c 0x0d 0x0e 0x0f))

(def test-key-192 
  (vector 0x00 0x01 0x02 0x03
          0x04 0x05 0x06 0x07
          0x08 0x09 0x0a 0x0b
          0x0c 0x0d 0x0e 0x0f
          0x10 0x11 0x12 0x13
          0x14 0x15 0x16 0x17))

(def test-key-256 
  (vector 0x00 0x01 0x02 0x03
          0x04 0x05 0x06 0x07
          0x08 0x09 0x0a 0x0b
          0x0c 0x0d 0x0e 0x0f
          0x10 0x11 0x12 0x13
          0x14 0x15 0x16 0x17
          0x18 0x19 0x1a 0x1b
          0x1c 0x1d 0x1e 0x1f))

(defn test-encrypt-block [state key]
  (encrypt-block state key))

(defn test-128-encrypt-block []
  (encrypt-block test-state test-key-128))

(defn test-192-encrypt-block []
  (encrypt-block test-state test-key-192))

(defn test-256-encrypt-block []
  (encrypt-block test-state test-key-256))

(defn test-all-encrypt-block []
  (map #(encrypt-block test-state %) 
       (vector test-key-128 test-key-192 test-key-256)))

(defn test-decrypt-block [state key]
  (decrypt-block state key))

(defn test-128-decrypt-block []
  (decrypt-block test-decrypt-state-128 test-key-128))

(defn test-192-decrypt-block []
  (decrypt-block test-decrypt-state-192 test-key-192))

(defn test-256-decrypt-block []
  (decrypt-block test-decrypt-state-256 test-key-256))

(defn test-all-decrypt-block []
  (map #(decrypt-block %1 %2) 
       (vector test-decrypt-state-128
               test-decrypt-state-192
               test-decrypt-state-256)
       (vector test-key-128
               test-key-192
               test-key-256)))

(defn both [key]
  (fn []
    (mapv #(Long/toHexString %) 
          (decrypt-block
           (encrypt-block test-state key) key))))

(defn test-128-both []
  ((both test-key-128)))

(defn test-192-both []
  ((both test-key-192)))

(defn test-256-both []
  ((both test-key-256)))
