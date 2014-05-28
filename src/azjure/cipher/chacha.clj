;; [chacha]: http://cr.yp.to/chacha/chacha-20080128.pdf
;; [S20]: http://cr.yp.to/snuffle/spec.pdf

(ns azjure.cipher.chacha
  "## ChaCha Cipher

  Implemented to meet the spec at [http://cr.yp.to/chacha/chacha-20080128.pdf]
  [chacha]"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.cipher.streamcipher :refer :all]
            [azjure.encoders :refer :all]
            [azjure.libbyte :refer :all]
            [azjure.libmod :refer [+modw]]))

(def ^{:private true
       :added   "0.2.0"}
  key-sizes
  "#### key-sizes
  ChaCha supports keys of 128 or 256 bits."
  [128 256])

(def ^{:private true
       :added   "0.2.0"}
  iv-size
  "#### iv-size
  ChaCha supports an IV (nonce) size of 64-bits."
  64)

(def ^{:private true
       :added   "0.2.0"}
  keystream-size
  "#### keystream-size
  ChaCha can generate 2^70 keystream bytes with the same key and nonce"
  "2^70")

(def ^{:private true
       :added   "0.2.0"}
  sigma
  "#### sigma
  Used during ChaCha expansion for 256-bit keys."
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x33]
   [0x32 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(def ^{:private true
       :added   "0.2.0"}
  tau
  "#### tau
  Used during ChaCha expansion for 128-bit keys."
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x31]
   [0x36 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(defn- quarter-subround
  "### quarter-subround
  A quarter subround.

  Represents a vector of two values:

    [w = (x + y mod 2<sup>32</sup>)
     ((w ^ z) <<< shift)]"
  {:added "0.2.0"}
  [[a b c d] shift]
  (cond
    (or (= shift 16) (= shift 8)) (let [a (+modw a b)]
                                    [a b c (<<< (bit-xor a d) shift)])
    (or (= shift 12) (= shift 7)) (let [c (+modw c d)]
                                    [a (<<< (bit-xor c b) shift) c d])))

(defn- quarter-round
  "### quarter-round
  quarterround function as defined in [ChaCha Spec][chacha]"
  {:added "0.2.0"}
  [[a b c d]]
  (vec (reduce quarter-subround [a b c d] [16 12 8 7])))

(defn- double-round
  "### double-round
  doubleround function as defined in [ChaCha Spec][chacha]

  Note this counts as two rounds of ChaCha, as each word in the 16-word input is
  modified twice.

  Takes a 16-word vector and evaluates to a 16-word vector."
  {:added "0.2.0"}
  [[x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15] _]
  (let [[[x0 x4 x8 x12]
         [x1 x5 x9 x13]
         [x2 x6 x10 x14]
         [x3 x7 x11 x15]] (mapv quarter-round [[x0 x4 x8 x12]
                                               [x1 x5 x9 x13]
                                               [x2 x6 x10 x14]
                                               [x3 x7 x11 x15]])
        [[x0 x5 x10 x15]
         [x1 x6 x11 x12]
         [x2 x7 x8 x13]
         [x3 x4 x9 x14]] (mapv quarter-round [[x0 x5 x10 x15]
                                              [x1 x6 x11 x12]
                                              [x2 x7 x8 x13]
                                              [x3 x4 x9 x14]])]
    [x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15]))

(defn- little-endian
  "### little-endian
  Generate the little endian form of a word (32-bit) value.

  Evaluates to:

    b<sub>0</sub> + 2<sup>8</sup>b<sub>1</sub> + 2<sup>16</sup>b<sub>2</sub> +
    2<sup>24</sup>b<sub>3</sub>"
  {:added "0.2.0"}
  [bv]
  (ubv->x bv :le true))

(defn- chacha-hash
  "### chacha-hash
  Calculate ChaCha(*x*) by performing double-round 4 times on the
  little-endian form of the bytes, and adding that mod<sub>32</sub> with the
  bytes.  The result is then converted back to a vector of words."
  {:added "0.2.0"}
  [x r]
  (let [bytes (map little-endian (partition 4 x))]
    (->> (range (/ r 2))
         (reduce double-round bytes)
         (mapv +modw bytes)
         (mapv #(word-bytes % true))
         (reduce into))))

(defn- v
  "### v
  Generate a lazy sequence of v's for ChaCha<sub>k</sub>(*v*) with the given
  8-byte nonce.

  Evaluates to a lazy sequence of 16-byte vectors."
  {:added "0.2.0"}
  [nonce]
  {:pre [(vector? nonce)
         (= 8 (count nonce))
         (every-byte? nonce)]}
  (map into (map #(dword-bytes % true) (range)) (repeat nonce)))

(defn- usbv32?
  "### usbv32
  Is the given vector 32 unsigned bytes long?"
  {:added "0.2.0"}
  [v]
  (and (every-byte? v) (= 32 (count v))))

(defn- chacha-expansion
  "### chacha-expansion
  Expand the 16 or 32-byte key *k* and the 16-byte vector *v* into a 64-byte
  vector using sigma or tau depending on the key length.

  Evaluates to a 64-byte vector."
  {:added "0.2.0"}
  [k v]
  (reduce into
          (if (usbv32? k)
            [(reduce into sigma) (subvec k 0 16) (subvec k 16) v]
            [(reduce into tau) k k v])))

(defn- chacha-kn
  "### chacha-kn
  Calculate ChaCha<sub>*k*</sub>(*n*) where *k* is a 16 or 32-byte key, and
  *n* is a 16-byte vector.

  Evaluates to a 64-byte vector encrypted with Salsa20."
  {:added "0.2.0"}
  [r]
  (fn [k n]
    (chacha-hash (chacha-expansion k n) r)))

(defn- chacha-encrypt
  "### chacha-encrypt
  Encrypt the given sequence *xs* under the 16 or 32-byte key *k* and the given
  8-byte nonce *n*.

  Evaluates to a lazy sequence of 64-byte sequences."
  {:added "0.2.0"}
  [xs m]
  (map #(map bit-xor %1 ((chacha-kn (:rounds m)) (:key m) %2))
       (partition-all 64 xs) (v (:nonce m))))

(defmethod initialize :chacha [m] m)
(defmethod keysizes-bits :chacha [_] key-sizes)
(defmethod iv-size-bits :chacha [_] iv-size)
(defmethod keystream-size-bytes :chacha [_] keystream-size)
(defmethod generate-keystream :chacha [m xs] (chacha-encrypt xs m))