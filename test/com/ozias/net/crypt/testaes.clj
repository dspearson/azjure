;; ## Test AES Encryption Engine
(ns ^{:author "Jason Ozias"}
     com.ozias.net.crypt.testaes
     (:require 
      [com.ozias.net.crypt.aes
       :refer [process-block]]))

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

(defn test-encrypt-block [state key]
  (process-block state key true))

(defn test-128-encrypt-block []
  (process-block test-state test-key-128 true))

(defn test-192-encrypt-block []
  (process-block test-state test-key-192 true))

(defn test-256-encrypt-block []
  (process-block test-state test-key-256 true))

(defn test-all-encrypt-block []
  (map #(process-block test-state % true) 
       (vector test-key-128 test-key-192 test-key-256)))

(defn test-decrypt-block [state key]
  (process-block state key false))

(defn test-128-decrypt-block []
  (process-block test-decrypt-state-128 test-key-128 false))

(defn test-192-decrypt-block []
  (process-block test-decrypt-state-192 test-key-192 false))

(defn test-256-decrypt-block []
  (process-block test-decrypt-state-256 test-key-256 false))

(defn test-all-decrypt-block []
  (map #(process-block %1 %2 false) 
       (vector test-decrypt-state-128
               test-decrypt-state-192
               test-decrypt-state-256)
       (vector test-key-128
               test-key-192
               test-key-256)))

(defn both [key]
  (fn []
    (mapv #(Long/toHexString %) 
          (process-block
           (process-block test-state key true) key false))))

(defn test-128-both []
  ((both test-key-128)))

(defn test-192-both []
  ((both test-key-192)))

(defn test-256-both []
  ((both test-key-256)))
