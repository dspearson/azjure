;; [xtea]: http://en.wikipedia.org/wiki/XTEA

(ns azjure.cipher.xtea
  "## XTEA Cipher

  Implemented to meet the spec at [http://en.wikipedia.org/wiki/XTEA] [xtea]"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.libbyte :refer :all]
            [azjure.libmod :refer :all]))

(def ^{:private true
       :added   "0.2.0"}
  key-sizes
  "#### key-sizes
  XTEA supports 128-bit keys"
  [128])

(def ^{:private true
       :added   "0.2.0"}
  block-size
  "#### block-size
  XTEA operates on 64-bit blocks."
  64)

(def ^{:private true
       :added   "0.2.0"}
  delta
  "#### delta
  Golden ratio remainder."
  0x9E3779B9)

(defn- calc-y
  "### calc-y
  XTEA y calculation"
  {:added "0.2.0"}
  [key enc]
  (fn [[y z sum]]
    ((if enc +modw -modw) y
     (bit-xor
       (+modw (bit-xor (bsl32 z 4) (bsr32 z 5)) z)
       (+modw sum (nth key (bit-and sum 3)))))))

(defn- calc-z
  "### calc-z
  XTEA z calculation"
  {:added "0.2.0"}
  [key enc]
  (fn [[y z sum]]
    ((if enc +modw -modw) z
     (bit-xor
       (+modw (bit-xor (bsl32 y 4) (bsr32 y 5)) y)
       (+modw sum (nth key (bit-and (bsr32 sum 11) 3)))))))

(defn- encipher-round
  "### encipher-round
  Encipher round"
  {:added "0.2.0"}
  [key]
  (fn [[y z] round]
    (let [yfn (calc-y key true)
          zfn (calc-z key true)
          ny (yfn [y z (*modw round delta)])]
      [ny (zfn [ny z (*modw (inc round) delta)])])))

(defn- decipher-round
  "### decipher-round
  Decipher round"
  {:added "0.2.0"}
  [key]
  (fn [[y z] round]
    (let [yfn (calc-y key false)
          zfn (calc-z key false)
          nz (zfn [y z (*modw (inc round) delta)])]
      [(yfn [y nz (*modw round delta)]) nz])))

(defn- cipher
  "### cipher
  XTEA cipher"
  {:added "0.2.0"}
  [bytes key enc]
  {:pre [(vector? key)
         (= (count bytes) 8)
         (= (count key) 16)]}
  (let [c-words (mapv bytes-word (partition 4 bytes))
        key-words (mapv bytes-word (partition 4 key))
        rng (if enc (range 32) (range 31 -1 -1))
        roundfn (if enc (encipher-round key-words) (decipher-round key-words))]
    (reduce into (mapv word-bytes (reduce roundfn c-words rng)))))

(defmethod initialize :xtea [m] m)
(defmethod keysizes-bits :xtea [_] key-sizes)
(defmethod blocksize-bits :xtea [_] block-size)
(defmethod encrypt-block :xtea [m block] (cipher block (:key m) true))
(defmethod decrypt-block :xtea [m block] (cipher block (:key m) false))