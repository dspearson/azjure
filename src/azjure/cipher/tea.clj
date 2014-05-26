;; [tea]: http://citeseer.ist.psu.edu/viewdoc/download

(ns azjure.cipher.tea
  "## TEA Cipher

  Implemented to meet the spec at
  [http://citeseer.ist.psu.edu/viewdoc/download] [tea]"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.libbyte :refer :all]
            [azjure.libmod :refer :all]))

(def ^{:private true
       :added   "0.2.0"}
  key-sizes
  "#### key-sizes
  TEA supports 128-bit keys"
  [128])

(def ^{:private true
       :added   "0.2.0"}
  block-size
  "#### block-size
  TEA operates on 64-bit blocks."
  64)

(def ^{:private true
       :added "0.2.0"}
  delta
  "### delta
  Golden ratio remainder."
  0x9E3779B9)

(defn- tea
  "### tea
  TEA encryption"
  {:added "0.2.0"}
  [sum enc]
  (fn [[w0 w1 w2 w3]]
    ((if enc +modw -modw) w0
     (bit-xor (+modw (bsl32 w1 4) w2)
              (+modw w1 sum)
              (+modw (bsr32 w1 5) w3)))))

(defn- encipher-round
  "### encipher-round
  TEA encipher round"
  {:added "0.2.0"}
  [[a b c d]]
  (fn [[y z] round]
    (let [teafn (tea (*modw (inc round) delta) true)
          ny (teafn [y z a b])]
      [ny (teafn [z ny c d])])))

(defn- decipher-round
  "### decipher-round
  TEA decryption round"
  {:added "0.2.0"}
  [[a b c d]]
  (fn [[y z] round]
    (let [teafn (tea (*modw (inc round) delta) false)
          nz (teafn [z y c d])]
      [(teafn [y nz a b]) nz])))

(defn- cipher
  "### cipher
  TEA cipher"
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

(defmethod initialize :tea [m] m)
(defmethod keysizes-bits :tea [_] key-sizes)
(defmethod blocksize-bits :tea [_] block-size)
(defmethod encrypt-block :tea [m block] (cipher block (:key m) true))
(defmethod decrypt-block :tea [m block] (cipher block (:key m) false))