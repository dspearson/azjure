;; ## Camellia Cipher
;; Designed to meet the spec at
;; [RFC3713](http://tools.ietf.org/html/rfc3713)
(ns ^{:author "Jason Ozias"}
    net.ozias.crypt.cipher.camellia
    (:require [clojure.string :refer (join)]
              (net.ozias.crypt [libbyte :refer [<<< bytes-dword]]
                               [libcrypt :refer (to-hex)])
              [net.ozias.crypt.cipher.blockcipher :refer [BlockCipher]]))

(def mask128 (BigInteger. "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" 16))
(def mask64  (BigInteger. "FFFFFFFFFFFFFFFF" 16))
(def mask32  (BigInteger. "FFFFFFFF" 16))
(def mask8   (BigInteger. "FF" 16))
(def sigma1  (BigInteger. "A09E667F3BCC908B" 16))
(def sigma2  (BigInteger. "B67AE8584CAA73B2" 16))
(def sigma3  (BigInteger. "C6EF372FE94F82BE" 16))
(def sigma4  (BigInteger. "54FF53A5F1D36F1C" 16))
(def sigma5  (BigInteger. "10E527FADE682D1D" 16))
(def sigma6  (BigInteger. "B05688C2B3E6C1FD" 16))

(def sbox1 
  [0x70 0x82 0x2c 0xec 0xb3 0x27 0xc0 0xe5 0xe4 0x85 0x57 0x35 0xea 0x0c 0xae 0x41
   0x23 0xef 0x6b 0x93 0x45 0x19 0xa5 0x21 0xed 0x0e 0x4f 0x4e 0x1d 0x65 0x92 0xbd
   0x86 0xb8 0xaf 0x8f 0x7c 0xeb 0x1f 0xce 0x3e 0x30 0xdc 0x5f 0x5e 0xc5 0x0b 0x1a
   0xa6 0xe1 0x39 0xca 0xd5 0x47 0x5d 0x3d 0xd9 0x01 0x5a 0xd6 0x51 0x56 0x6c 0x4d
   0x8b 0x0d 0x9a 0x66 0xfb 0xcc 0xb0 0x2d 0x74 0x12 0x2b 0x20 0xf0 0xb1 0x84 0x99
   0xdf 0x4c 0xcb 0xc2 0x34 0x7e 0x76 0x05 0x6d 0xb7 0xa9 0x31 0xd1 0x17 0x04 0xd7
   0x14 0x58 0x3a 0x61 0xde 0x1b 0x11 0x1c 0x32 0x0f 0x9c 0x16 0x53 0x18 0xf2 0x22
   0xfe 0x44 0xcf 0xb2 0xc3 0xb5 0x7a 0x91 0x24 0x08 0xe8 0xa8 0x60 0xfc 0x69 0x50
   0xaa 0xd0 0xa0 0x7d 0xa1 0x89 0x62 0x97 0x54 0x5b 0x1e 0x95 0xe0 0xff 0x64 0xd2
   0x10 0xc4 0x00 0x48 0xa3 0xf7 0x75 0xdb 0x8a 0x03 0xe6 0xda 0x09 0x3f 0xdd 0x94
   0x87 0x5c 0x83 0x02 0xcd 0x4a 0x90 0x33 0x73 0x67 0xf6 0xf3 0x9d 0x7f 0xbf 0xe2
   0x52 0x9b 0xd8 0x26 0xc8 0x37 0xc6 0x3b 0x81 0x96 0x6f 0x4b 0x13 0xbe 0x63 0x2e
   0xe9 0x79 0xa7 0x8c 0x9f 0x6e 0xbc 0x8e 0x29 0xf5 0xf9 0xb6 0x2f 0xfd 0xb4 0x59
   0x78 0x98 0x06 0x6a 0xe7 0x46 0x71 0xba 0xd4 0x25 0xab 0x42 0x88 0xa2 0x8d 0xfa
   0x72 0x07 0xb9 0x55 0xf8 0xee 0xac 0x0a 0x36 0x49 0x2a 0x68 0x3c 0x38 0xf1 0xa4
   0x40 0x28 0xd3 0x7b 0xbb 0xc9 0x43 0xc1 0x15 0xe3 0xad 0xf4 0x77 0xc7 0x80 0x9e])

(def sbox2
  [0xe0 0x05 0x58 0xd9 0x67 0x4e 0x81 0xcb 0xc9 0x0b 0xae 0x6a 0xd5 0x18 0x5d 0x82
   0x46 0xdf 0xd6 0x27 0x8a 0x32 0x4b 0x42 0xdb 0x1c 0x9e 0x9c 0x3a 0xca 0x25 0x7b
   0x0d 0x71 0x5f 0x1f 0xf8 0xd7 0x3e 0x9d 0x7c 0x60 0xb9 0xbe 0xbc 0x8b 0x16 0x34
   0x4d 0xc3 0x72 0x95 0xab 0x8e 0xba 0x7a 0xb3 0x02 0xb4 0xad 0xa2 0xac 0xd8 0x9a
   0x17 0x1a 0x35 0xcc 0xf7 0x99 0x61 0x5a 0xe8 0x24 0x56 0x40 0xe1 0x63 0x09 0x33
   0xbf 0x98 0x97 0x85 0x68 0xfc 0xec 0x0a 0xda 0x6f 0x53 0x62 0xa3 0x2e 0x08 0xaf
   0x28 0xb0 0x74 0xc2 0xbd 0x36 0x22 0x38 0x64 0x1e 0x39 0x2c 0xa6 0x30 0xe5 0x44
   0xfd 0x88 0x9f 0x65 0x87 0x6b 0xf4 0x23 0x48 0x10 0xd1 0x51 0xc0 0xf9 0xd2 0xa0
   0x55 0xa1 0x41 0xfa 0x43 0x13 0xc4 0x2f 0xa8 0xb6 0x3c 0x2b 0xc1 0xff 0xc8 0xa5
   0x20 0x89 0x00 0x90 0x47 0xef 0xea 0xb7 0x15 0x06 0xcd 0xb5 0x12 0x7e 0xbb 0x29
   0x0f 0xb8 0x07 0x04 0x9b 0x94 0x21 0x66 0xe6 0xce 0xed 0xe7 0x3b 0xfe 0x7f 0xc5
   0xa4 0x37 0xb1 0x4c 0x91 0x6e 0x8d 0x76 0x03 0x2d 0xde 0x96 0x26 0x7d 0xc6 0x5c
   0xd3 0xf2 0x4f 0x19 0x3f 0xdc 0x79 0x1d 0x52 0xeb 0xf3 0x6d 0x5e 0xfb 0x69 0xb2
   0xf0 0x31 0x0c 0xd4 0xcf 0x8c 0xe2 0x75 0xa9 0x4a 0x57 0x84 0x11 0x45 0x1b 0xf5
   0xe4 0x0e 0x73 0xaa 0xf1 0xdd 0x59 0x14 0x6c 0x92 0x54 0xd0 0x78 0x70 0xe3 0x49
   0x80 0x50 0xa7 0xf6 0x77 0x93 0x86 0x83 0x2a 0xc7 0x5b 0xe9 0xee 0x8f 0x01 0x3d])

(def sbox3
  [0x38 0x41 0x16 0x76 0xd9 0x93 0x60 0xf2 0x72 0xc2 0xab 0x9a 0x75 0x06 0x57 0xa0
   0x91 0xf7 0xb5 0xc9 0xa2 0x8c 0xd2 0x90 0xf6 0x07 0xa7 0x27 0x8e 0xb2 0x49 0xde
   0x43 0x5c 0xd7 0xc7 0x3e 0xf5 0x8f 0x67 0x1f 0x18 0x6e 0xaf 0x2f 0xe2 0x85 0x0d
   0x53 0xf0 0x9c 0x65 0xea 0xa3 0xae 0x9e 0xec 0x80 0x2d 0x6b 0xa8 0x2b 0x36 0xa6
   0xc5 0x86 0x4d 0x33 0xfd 0x66 0x58 0x96 0x3a 0x09 0x95 0x10 0x78 0xd8 0x42 0xcc
   0xef 0x26 0xe5 0x61 0x1a 0x3f 0x3b 0x82 0xb6 0xdb 0xd4 0x98 0xe8 0x8b 0x02 0xeb
   0x0a 0x2c 0x1d 0xb0 0x6f 0x8d 0x88 0x0e 0x19 0x87 0x4e 0x0b 0xa9 0x0c 0x79 0x11
   0x7f 0x22 0xe7 0x59 0xe1 0xda 0x3d 0xc8 0x12 0x04 0x74 0x54 0x30 0x7e 0xb4 0x28
   0x55 0x68 0x50 0xbe 0xd0 0xc4 0x31 0xcb 0x2a 0xad 0x0f 0xca 0x70 0xff 0x32 0x69
   0x08 0x62 0x00 0x24 0xd1 0xfb 0xba 0xed 0x45 0x81 0x73 0x6d 0x84 0x9f 0xee 0x4a
   0xc3 0x2e 0xc1 0x01 0xe6 0x25 0x48 0x99 0xb9 0xb3 0x7b 0xf9 0xce 0xbf 0xdf 0x71
   0x29 0xcd 0x6c 0x13 0x64 0x9b 0x63 0x9d 0xc0 0x4b 0xb7 0xa5 0x89 0x5f 0xb1 0x17
   0xf4 0xbc 0xd3 0x46 0xcf 0x37 0x5e 0x47 0x94 0xfa 0xfc 0x5b 0x97 0xfe 0x5a 0xac
   0x3c 0x4c 0x03 0x35 0xf3 0x23 0xb8 0x5d 0x6a 0x92 0xd5 0x21 0x44 0x51 0xc6 0x7d
   0x39 0x83 0xdc 0xaa 0x7c 0x77 0x56 0x05 0x1b 0xa4 0x15 0x34 0x1e 0x1c 0xf8 0x52
   0x20 0x14 0xe9 0xbd 0xdd 0xe4 0xa1 0xe0 0x8a 0xf1 0xd6 0x7a 0xbb 0xe3 0x40 0x4f])

(def sbox4
  [0x70 0xaa 0x82 0xd0 0x2c 0xa0 0xec 0x7d 0xb3 0xa1 0x27 0x89 0xc0 0x62 0xe5 0x97
   0xe4 0x54 0x85 0x5b 0x57 0x1e 0x35 0x95 0xea 0xe0 0x0c 0xff 0xae 0x64 0x41 0xd2
   0x23 0x10 0xef 0xc4 0x6b 0x00 0x93 0x48 0x45 0xa3 0x19 0xf7 0xa5 0x75 0x21 0xdb
   0xed 0x8a 0x0e 0x03 0x4f 0xe6 0x4e 0xda 0x1d 0x09 0x65 0x3f 0x92 0xdd 0xbd 0x94
   0x86 0x87 0xb8 0x5c 0xaf 0x83 0x8f 0x02 0x7c 0xcd 0xeb 0x4a 0x1f 0x90 0xce 0x33
   0x3e 0x73 0x30 0x67 0xdc 0xf6 0x5f 0xf3 0x5e 0x9d 0xc5 0x7f 0x0b 0xbf 0x1a 0xe2
   0xa6 0x52 0xe1 0x9b 0x39 0xd8 0xca 0x26 0xd5 0xc8 0x47 0x37 0x5d 0xc6 0x3d 0x3b
   0xd9 0x81 0x01 0x96 0x5a 0x6f 0xd6 0x4b 0x51 0x13 0x56 0xbe 0x6c 0x63 0x4d 0x2e
   0x8b 0xe9 0x0d 0x79 0x9a 0xa7 0x66 0x8c 0xfb 0x9f 0xcc 0x6e 0xb0 0xbc 0x2d 0x8e
   0x74 0x29 0x12 0xf5 0x2b 0xf9 0x20 0xb6 0xf0 0x2f 0xb1 0xfd 0x84 0xb4 0x99 0x59
   0xdf 0x78 0x4c 0x98 0xcb 0x06 0xc2 0x6a 0x34 0xe7 0x7e 0x46 0x76 0x71 0x05 0xba
   0x6d 0xd4 0xb7 0x25 0xa9 0xab 0x31 0x42 0xd1 0x88 0x17 0xa2 0x04 0x8d 0xd7 0xfa
   0x14 0x72 0x58 0x07 0x3a 0xb9 0x61 0x55 0xde 0xf8 0x1b 0xee 0x11 0xac 0x1c 0x0a
   0x32 0x36 0x0f 0x49 0x9c 0x2a 0x16 0x68 0x53 0x3c 0x18 0x38 0xf2 0xf1 0x22 0xa4
   0xfe 0x40 0x44 0x28 0xcf 0xd3 0xb2 0x7b 0xc3 0xbb 0xb5 0xc9 0x7a 0x43 0x91 0xc1
   0x24 0x15 0x08 0xe3 0xe8 0xad 0xa8 0xf4 0x60 0x77 0xfc 0xc7 0x69 0x80 0x50 0x9e])

(defn- to-bi 
  ([val radix]
     (BigInteger. (str val) radix))
  ([val]
     (to-bi val 10)))

(defn- gen-t [x]
  [(nth sbox1 (.shiftRight x 56))
   (nth sbox2 (.and (.shiftRight x 48) mask8))
   (nth sbox3 (.and (.shiftRight x 40) mask8))
   (nth sbox4 (.and (.shiftRight x 32) mask8))
   (nth sbox2 (.and (.shiftRight x 24) mask8))
   (nth sbox3 (.and (.shiftRight x 16) mask8))
   (nth sbox4 (.and (.shiftRight x 8) mask8))
   (nth sbox1 (.and x mask8))])

(defn- gen-y [[t1 t2 t3 t4 t5 t6 t7 t8]]
  [(bit-xor t1 t3 t4 t6 t7 t8)
   (bit-xor t1 t2 t4 t5 t7 t8)
   (bit-xor t1 t2 t3 t5 t6 t8)
   (bit-xor t2 t3 t4 t5 t6 t7)
   (bit-xor t1 t2 t6 t7 t8)
   (bit-xor t2 t3 t5 t7 t8)
   (bit-xor t3 t4 t5 t6 t8)
   (bit-xor t1 t4 t5 t6 t7)])

(defn- ffn [fin subkey]
  (let [ys (-> (.xor fin subkey)
               (gen-t)
               (gen-y))]
    (reduce #(.xor (to-bi %1) (to-bi %2)) 0 (mapv #(.shiftLeft (to-bi %1) %2) ys (range 56 -1 -8)))))

(defn- key-schedule [key]
  key)

(defn- fl [fin subkey]
  (let [x1 (.shiftRight fin 32)
        x2 (.and fin mask32)
        k1 (.shiftRight subkey 32)
        k2 (.and subkey mask32)
        x2 (.xor x2 (<<< (.and x1 k1) 1 32))
        x1 (.xor x1 (.or x2 k2))]
    (.or (.shiftLeft x1 32) x2)))

(defn- flinv [fin subkey]
  (let [y1 (.shiftRight fin 32)
        y2 (.and fin mask32)
        k1 (.shiftRight subkey 32)
        k2 (.and subkey mask32)
        y1 (.xor y1 (.or y2 k2))
        y2 (.xor y2 (<<< (.and y1 k1) 1 32))]
    (.or (.shiftLeft y1 32) y2)))

;; ### expand-key
;; Expands the key to to 2 vectors of 2 64-bit
;; double words each.
;;
;; Evaluates to 2 vectors of 2 64-bit words
;; [0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
;;  0xfe 0xdc 0xba 0x98 0x76 0x54 0x32 0x10]
;; [0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
;;  0xfe 0xdc 0xba 0x98 0x76 0x54 0x32 0x10
;;  0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77]
;; [0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
;;  0xfe 0xdc 0xba 0x98 0x76 0x54 0x32 0x10
;;  0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77
;;  0x88 0x99 0xaa 0xbb 0xcc 0xdd 0xee 0xff]
(defn- expand-key [key]
  (let [kw (->> (partition 8 key)
                (mapv #(bytes-dword %)))]
    (condp = (count key)
      16 [kw [0 0]]
      24 [(vec (take 2 kw)) [(last kw) (bit-not (last kw))]]
      32 ((juxt #(vec (take 2 %)) #(subvec % 2 (count %))) kw))))

;; ### process-block
;; Process a block for encryption or decryption.
;;
;; 1. <em>block</em>: A vector of four 32-bit words representing a block.
;; 2. <em>key</em>: A vector of byte values (0-255) representing a 
;; key of 128, 192, or 256 bits.
;; 3. <em>enc</em>: true if you are encrypting the block, false
;; if you are decrypting the block.
;;
;; Evaluates to a vector of four 32-bit words.
(defn- process-block [block key enc]
  (let [ks (expand-key key)
        kl (-> (mapv (partial to-hex) (first ks))
               (join)
               (clojure.string/replace #"0x" "")
               (BigInteger. 16))
        kr (-> (mapv (partial to-hex) (last ks))
               (join)
               (clojure.string/replace #"0x" "")
               (BigInteger. 16))
        _ (println (str "KL:  " (to-hex kl 32)))
        _ (println (str "KR:  " (to-hex kr 32)))
        d1 (.shiftRight (.xor kl kr) 64)
        d2 (.and (.xor kl kr) mask64)
        d2 (.xor d2 (ffn d1 sigma1))
        d1 (.xor d1 (ffn d2 sigma2))
        d1 (.xor d1 (.shiftRight kl 64))
        d2 (.xor d2 (.and kl mask64))
        d2 (.xor d2 (ffn d1 sigma3))
        d1 (.xor d1 (ffn d2 sigma4))
        ka (.or (.shiftLeft d1 64) d2)
        d1 (.shiftRight (.xor ka kr) 64)
        d2 (.and (.xor ka kr) mask64)
        d2 (.xor d2 (ffn d1 sigma5))
        d1 (.xor d1 (ffn d2 sigma6))
        kb (.or (.shiftLeft d1 64) d2)
        _ (println (str "KA:  " (to-hex ka)))
        _ (println (str "KB:  " (to-hex kb)))
        kw1 (.shiftRight (<<< kl 0 128) 64)
        kw2 (.and (<<< kl 0 128) mask64)
        kw3 (.shiftRight (<<< ka 111 128) 64)
        kw4 (.and (<<< ka 111 128) mask64)
        k1 (.shiftRight (<<< ka 0 128) 64)
        k2 (.and (<<< ka 0 128) mask64)
        k3 (.shiftRight (<<< kl 15 128) 64)
        k4 (.and (<<< kl 15 128) mask64)
        k5 (.shiftRight (<<< ka 15 128) 64)
        k6 (.and (<<< ka 15 128) mask64)
        k7 (.shiftRight (<<< kl 45 128) 64)
        k8 (.and (<<< kl 45 128) mask64)
        k9 (.shiftRight (<<< ka 45 128) 64)
        k10 (.and (<<< kl 60 128) mask64)
        k11 (.shiftRight (<<< ka 60 128) 64)
        k12 (.and (<<< ka 60 128) mask64)
        k13 (.shiftRight (<<< kl 94) 64)
        k14 (.and (<<< kl 94) mask64)
        k15 (.shiftRight (<<< ka 94) 64)
        k16 (.and (<<< ka 94) mask64)
        k17 (.shiftRight (<<< kl 111) 64)
        k18 (.and (<<< kl 111) mask64)
        ke1 (.shiftRight (<<< ka 30 128) 64)
        ke2 (.and (<<< ka 30 128) mask64)
        ke3 (.shiftRight (<<< kl 77 128) 64)
        ke4 (.and (<<< kl 77 128) mask64)
        _ (mapv #(println (str "KW" %1 ": " (to-hex %2 16))) (range 1 5) [kw1 kw2 kw3 kw4])
        _ (mapv #(println (str "KE" %1 ": " (to-hex %2 16))) (range 1 5) [ke1 ke2 ke3 ke4])
        _ (mapv #(println (str "K" %1 ":  " (to-hex %2 16))) (range 1 10) [k1 k2 k3 k4 k5 k6 k7 k8 k9])
        _ (mapv #(println (str "K" %1 ": " (to-hex %2 16))) (range 10 19) [k10 k11 k12 k12 k14 k15 k16 k17 k18])
        d1 (BigInteger. "0123456789abcdef" 16)
        d2 (BigInteger. "fedcba9876543210" 16)
        d1 (.xor d1 kw1)
        d2 (.xor d2 kw2)
        d2 (.xor d2 (ffn d1 k1))
        d1 (.xor d1 (ffn d2 k2))
        d2 (.xor d2 (ffn d1 k3))
        d1 (.xor d1 (ffn d2 k4))
        d2 (.xor d2 (ffn d1 k5))
        d1 (.xor d1 (ffn d2 k6))
        d1 (fl d1 ke1)
        d2 (flinv d2 ke2)
        d2 (.xor d2 (ffn d1 k7))
        d1 (.xor d1 (ffn d2 k8))
        d2 (.xor d2 (ffn d1 k9))
        d1 (.xor d1 (ffn d2 k10))
        d2 (.xor d2 (ffn d1 k11))
        d1 (.xor d1 (ffn d2 k12))
        d1 (fl d1 ke3)
        d2 (flinv d2 ke4)
        d2 (.xor d2 (ffn d1 k13))
        d1 (.xor d1 (ffn d2 k14))
        d2 (.xor d2 (ffn d1 k15))
        d1 (.xor d1 (ffn d2 k16))
        d2 (.xor d2 (ffn d1 k17))
        d1 (.xor d1 (ffn d2 k18))
        d2 (.xor d2 kw3)
        d1 (.xor d1 kw4)
        _ (println (str "D1:  " (to-hex d1)))
        _ (println (str "D2:  " (to-hex d2)))]
  (.or (.shiftLeft d2 64) d1)))

;; ### Camellia
;; Extend the BlockCipher protocol through the Camellia record type.
(defrecord CAST6 []
  BlockCipher
  (encrypt-block [_ block key]
    (process-block block key true))
  (decrypt-block [_ block key]
    (process-block block key false))
  (blocksize [_]
    128))
