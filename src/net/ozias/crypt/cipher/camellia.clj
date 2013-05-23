;; ## Camellia Cipher
;; Designed to meet the spec at
;; [RFC3713](http://tools.ietf.org/html/rfc3713)
(ns ^{:author "Jason Ozias"}
    net.ozias.crypt.cipher.camellia
    (:require (net.ozias.crypt [libbyte :refer (bytes-dword)]
                               [libcrypt :refer (to-hex)])
              [net.ozias.crypt.cipher.blockcipher :refer [BlockCipher]]))

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
  (let [l (count key)
        kw (->> (partition 8 key)
                (mapv #(bytes-dword %)))
        _ (println (mapv (partial to-hex) kw))
        _ (println (count kw))]
    (condp = l
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
        _ (println ks)]
;;        keys (if enc ks (flip-key-schedule ks))
;;        castfn (cast6 keys)]
;;    (->> (range 12)
;;         (reduce #(castfn %1 %2) block))))
  block))

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
