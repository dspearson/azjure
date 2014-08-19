;; [S20]: http://cr.yp.to/snuffle/spec.pdf

(ns azjure.cipher.salsa20
  "## Salsa20 Cipher

  Implemented to meet the spec at [http://cy.yp.to/snuffle/spec.pdf] [S20]"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.cipher.streamcipher :refer :all]
            [azjure.libbyte :refer :all]
            [azjure.libmod :refer [+modw]]))

(def ^{:private true
       :added   "0.2.0"}
  key-sizes
  "#### key-sizes
  Salsa20 supports keys of 128 or 256 bits."
  [128 256])

(def ^{:private true
       :added   "0.2.0"}
  iv-size
  "#### iv-size
  Salsa20 supports an IV (nonce) size of 64-bits."
  64)

(def ^{:private true
       :added   "0.2.0"}
  keystream-size
  "#### keystream-size
  Salsa20 can generate 2^70 keystream bytes with the same key and nonce"
  "2^70")

(def ^{:private true
       :added   "0.2.0"}
  sigma
  "#### sigma
  Used during Salsa20 expansion for 256-bit keys."
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x33]
   [0x32 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(def ^{:private true
       :added   "0.2.0"}
  tau
  "#### tau
  Used during Salsa20 expansion for 128-bit keys."
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x31]
   [0x36 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(defn- quarter-round
  "### quarter-round
  quarterround function as defined in [Salsa20 Spec][S20].

  Takes a 4-word vector and evaluates to a 4-word vector."
  {:added "0.2.0"}
  [[y0 y1 y2 y3]]
  (let [z1 (bit-xor y1 (<<< (+modw y0 y3) 7))
        z2 (bit-xor y2 (<<< (+modw z1 y0) 9))
        z3 (bit-xor y3 (<<< (+modw z2 z1) 13))
        z0 (bit-xor y0 (<<< (+modw z3 z2) 18))]
    [z0 z1 z2 z3]))

(defn- row-round
  "### row-round
  rowround function as defined in [Salsa20 Spec][S20]

  Takes a 16-word vector and evaluates to a 16-word vector."
  {:added "0.2.0"}
  [[y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]]
  (let [mx [[y0 y1 y2 y3]
            [y5 y6 y7 y4]
            [y10 y11 y8 y9]
            [y15 y12 y13 y14]]
        [[z0 z1 z2 z3]
         [z5 z6 z7 z4]
         [z10 z11 z8 z9]
         [z15 z12 z13 z14]] (map quarter-round mx)]
    [z0 z1 z2 z3 z4 z5 z6 z7 z8 z9 z10 z11 z12 z13 z14 z15]))

(defn- column-round
  "### column-round
  columnround function as defined in [Salsa20 Spec][S20]

  Takes a 16-word vector and evaluates to a 16-word vector."
  {:added "0.2.0"}
  [[x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15]]
  (let [mx [[x0 x4 x8 x12]
            [x5 x9 x13 x1]
            [x10 x14 x2 x6]
            [x15 x3 x7 x11]]
        [[y0 y4 y8 y12]
         [y5 y9 y13 y1]
         [y10 y14 y2 y6]
         [y15 y3 y7 y11]] (map quarter-round mx)]
    [y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]))

(defn- double-round
  "### double-round
  doubleround function as defined in [Salsa20 Spec][S20]

  Takes a 16-word vector and evaluates to a 16-word vector."
  {:added "0.2.0"}
  [xv]
  (row-round (column-round xv)))

(defn- little-endian
  "### little-endian
  Generate the little endian form of a word (32-bit) value.

  Evaluates to b<sub>0</sub> + 2<sup>8</sup>b<sub>1</sub> +
  2<sup>16</sup>b<sub>2</sub> + 2<sup>24</sup>b<sub>3</sub>"
  {:added "0.2.0"}
  [bv]
  (ubv->x bv :le true))

(defn- salsa20-hash
  "### salsa20-hash
  Calculate Salsa20(*x*) by performing double-round 10 times on the
  little-endian form of the bytes, and adding that mod<sub>32</sub> with the
  bytes.  The result is then converted back to a vector of words."
  {:added "0.2.0"}
  [x]
  (let [bytes (map little-endian (partition 4 x))]
    (->> (range 10)
         (reduce (fn [x _] (double-round x)) bytes)
         (mapv +modw bytes)
         (mapv #(word-bytes % true))
         (reduce into))))

(defn- v
  "### v
  Generate a lazy sequence of v's for Salsa20<sub>k</sub>(*v*) with the given
  8-byte nonce.

  Evaluates to a lazy sequence of 16-byte vectors."
  {:added "0.2.0"}
  [nonce]
  {:pre [(vector? nonce)
         (= 8 (count nonce))
         (every-unsigned-byte? nonce)]}
  (map into (repeat nonce) (map #(dword-bytes % true) (range))))

(defn- usbv32?
  "### usbv32
  Is the given vector 32 unsigned bytes long?"
  {:added "0.2.0"}
  [v]
  (and (every-unsigned-byte? v) (= 32 (count v))))

(defn- salsa20-expansion
  "### salsa20-expansion
  Expand the 16 or 32-byte key *k* and the 16-byte vector *v* into a 64-byte
  vector using sigma or tau depending on the key length.

  Evaluates to a 64-byte vector."
  {:added "0.2.0"}
  [k v]
  (->> (if (usbv32? k)
         (interleave sigma [(subvec k 0 16) v (subvec k 16) 0])
         (interleave tau [k v k 0]))
       (butlast)
       (reduce into)))

(defn- salsa20-kn
  "### salsa20-kn
  Calculate Salsa20<sub>*k*</sub>(*n*) where *k* is a 16 or 32-byte key, and
  *n* is a 16-byte vector.

  Evaluates to a 64-byte vector encrypted with Salsa20."
  {:added "0.2.0"}
  [k n]
  (salsa20-hash (salsa20-expansion k n)))

(defn- salsa20-encrypt
  "### salsa20-encrypt
  Encrypt the given sequence *xs* under the 16 or 32-byte key *k* and the given
  8-byte nonce *n*.

  Evaluates to a lazy sequence of 64-byte sequences."
  {:added "0.2.0"}
  [xs k n]
  (map #(map bit-xor %1 (salsa20-kn k %2)) (partition-all 64 xs) (v n)))

(defmethod initialize :salsa20 [m] m)
(defmethod keysizes-bits :salsa20 [_] key-sizes)
(defmethod iv-size-bits :salsa20 [_] iv-size)
(defmethod keystream-size-bytes :salsa20 [_] keystream-size)
(defmethod generate-keystream :salsa20 [m xs]
  (salsa20-encrypt xs (:key m) (:nonce m)))