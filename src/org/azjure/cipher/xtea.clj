;; ## XTEA
;; Extended Tiny Encryption Algorithm
(ns org.azjure.cipher.xtea
  (:require (org.azjure.cipher [cipher :refer (Cipher)]
                               [blockcipher :refer (BlockCipher)])
            [org.azjure.libcrypt :refer :all]
            [org.azjure.libbyte :refer :all]
            [taoensso.timbre.profiling :as profiling :refer (p profile)]))

(def ^{:doc "Golden ratio remainder."}
  delta 0x9E3779B9)

;y+= (z<<4 ^ z>>5) + z ^ sum + k[sum&3],
(defn- ^{:doc "XTEA y calculation"}
  calc-y [key enc]
  (fn [[y z sum]]
    (let [addsubfn (if enc +modw -modw)]
      ((if enc +modw -modw) y
       (bit-xor
        (+modw (bit-xor (bsl32 z 4)(bsr32 z 5)) z)
        (+modw sum (nth key (bit-and sum 3))))))))
  
;z+= (y<<4 ^ y>>5) + y ^ sum + k[sum>>11 &3] ;
(defn- ^{:doc "XTEA z calculation"}
  calc-z [key enc]
  (fn [[y z sum]]
    ((if enc +modw -modw) z
     (bit-xor
      (+modw (bit-xor (bsl32 y 4)(bsr32 y 5)) y)
      (+modw sum (nth key (bit-and (bsr32 sum 11) 3)))))))

(defn- ^{:doc "Encipher round"}
  encipher-round [key]
  (fn [[y z] round]
    (let [yfn (calc-y key true)
          zfn (calc-z key true)
          ny (yfn [y z (*modw round delta)])]
      [ny (zfn [ny z (*modw (inc round) delta)])])))

(defn- ^{:doc "Decipher round"}
  decipher-round [key]
  (fn [[y z] round]
    (let [yfn (calc-y key false)
          zfn (calc-z key false)
          nz (zfn [y z (*modw round delta)])]
      [(yfn [y nz (*modw (inc round) delta)]) nz])))

(defn- ^{:doc "TEA cipher algorithm"}
  cipher 
  ([bytes key enc]
     {:pre [(vector? bytes)(vector? key)
            (= (count bytes) 8)(= (count key) 16)]}
  (let [c-words (mapv bytes-word (partition 4 bytes))
        key-words (mapv bytes-word (partition 4 key))
        rng (if enc (range 32)(range 31 -1 -1))
        roundfn (if enc (encipher-round key-words)(decipher-round key-words))]
    (reduce roundfn c-words rng))))

;; ### XTEA
;; Extend the Cipher and BlockCipher thorough the XTEA record type

(defrecord XTEA []
  Cipher
  (initialize [_ {:keys [key] :as initmap}] 
    initmap)
  (keysizes-bytes [_] 
    [16])
  BlockCipher
  (encrypt-block [_ bytes {:keys [key] :as initmap}]
    (reduce into (mapv word-bytes (cipher (vec bytes) key true))))
  (decrypt-block [_ bytes {:keys [key] :as initmap}]
    (reduce into (mapv word-bytes (cipher (vec bytes) key false))))
  (blocksize [_] 64))
