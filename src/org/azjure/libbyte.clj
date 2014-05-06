;; ## libbyte
;; Byte manipulation library

(ns org.azjure.libbyte
  {:author "Jason Ozias"}
  (:require [clojure.math.numeric-tower :refer [expt]]))

(def ^{:doc "32-bit mask"}
  mask32 0xFFFFFFFF)

(defn indexed
  "Returns a lazy sequence of [index, item] pairs, where items come
  from 's' and indexes count up from zero.

  (indexed '(a b c d))  =>  ([0 a] [1 b] [2 c] [3 d])"
  [s]
  (map vector (iterate inc 0) s))

(defn positions
  "Returns a lazy sequence containing the positions at which pred
   is true for items in coll."
  [pred coll]
  (for [[idx elt] (indexed coll) :when (pred elt)] idx))

(defn byte->bits [byte]
  (vec (reverse (mapv #(if % 1 0) (mapv (partial bit-test byte) (range 8))))))

(defn bits->byte [bits]
  (reduce bit-set 0 (positions #{1} bits)))

;; ### get-byte
;; Get byte <em>num</em> out of the given word.  <em>num</em>
;; should be 1-4 where 1 is the least significant byte and 4
;; is the most significant byte.
;;
;;     (get-byte 0x11223344 4)
;;
;; evaluates to 0x11
(defn get-byte [num word]
  (let [shift (* 8 (dec num))
        sftfn (if (zero? shift) word (bit-shift-right word shift))]
    (bit-and sftfn 0xFF)))

;; ### last-byte
;; Evaluates to the least significant byte of the given word
(defn last-byte [word]
  (bit-and 0xff word))

;; ### bytes-word
;; Takes a vector of 4 bytes and creates
;; one 32-bit word composed of the 4 bytes.
;;
;;     (bytes-word [0x12 0xab 0x1f 0x3b])
;;
;; evaluates to
;; > 0x12ab1f3b
;;
;; This is the inverse of word-bytes.
(defn bytes-word
  ([vec le]
   (let [rng (if le (range 0 32 8) (range 24 -1 -8))]
     (reduce bit-or (map #(bit-shift-left (nth vec %1) %2) (range 4) rng))))
  ([vec]
   (bytes-word vec false)))

(defn bytes-dword [vec]
  (apply bit-or
         (map #(bit-shift-left (nth vec %1) %2)
              (range 8)
              (range 56 -1 -8))))

;; ### word-bytes
;; Takes a 32-bit word and creates a vector of 
;; the 4 bytes individually. If <em>le</em> 
;; (little endian) is true, the order of the vector
;; will be LSB to MSB. Otherwise, the order of the
;; vector will be MSB to LSB.
;;
;;     (word-bytes 0x12ab1f3b)
;;
;; evaluates to
;; > [0x12 0xab 0x1f 0x3b]
;;
;;     (word-bytes 0x12ab1f3b true)
;;
;; evaluates to
;; > [0x3b 0x1f 0xab 0x12]
;;
;; This is the inverse of byte-words.
(defn word-bytes
  ([word le]
   (let [rng (if le (range 0 32 8) (range 24 -1 -8))]
     (mapv #(last-byte (bit-shift-right word %)) rng)))
  ([word]
   (word-bytes word false)))

(defn dword-bytes
  ([dword le]
   (let [rng (if le (range 0 64 8) (range 56 -1 -8))]
     (mapv #(last-byte (bit-shift-right dword %)) rng)))
  ([dword]
   (dword-bytes dword false)))

;; ### reverse-bytes
;; Reverse the bytes in a word
;;
;;     (reverse-bytes 0x01234567)
;;
;; evaluates to
;; > 0x67452301
;; 
(defn reverse-bytes [word]
  (-> #(last-byte (bit-shift-right word %1))
      (mapv (range 0 32 8))
      (bytes-word)))

(defn- inv-shift [shift bits]
  (- bits shift))

(def minv-shift (memoize inv-shift))

(defn shift-dispatch [word shift bits]
  (cond
    (or (instance? BigInteger word) (> bits 32)) :a
    :else :default))

;; ### <<<
;; Circular left shift
;;
;; Shift a 32-bit word left by <em>shift</em> bits, shifting
;; the leftmost bits into the rightmost positions.
;;
;;     (<<< 0x12345678 8)
;;
;; evaluates to
;;
;; > 0x34567812
(defmulti <<<-mm shift-dispatch)

(defmethod <<<-mm :a [word shift bits]
  (let [biw (if (instance? BigInteger word) word (BigInteger. (str word)))
        sft (mod shift bits)
        mask (BigInteger. (str (dec (expt 2 bits))))]
    (if (zero? sft)
      word
      (.or
        (.and (.shiftLeft biw sft) mask)
        (.shiftRight biw (minv-shift sft bits))))))

(defmethod <<<-mm :default [word shift bits]
  (let [sft (mod shift bits)
        mask (dec (expt 2 bits))]
    (if (zero? sft)
      word
      (bit-or
        (bit-and (bit-shift-left word sft) mask)
        (bit-shift-right word (minv-shift sft bits))))))

(defn <<<
  ([word shift bits] (<<<-mm word shift bits))
  ([word shift] (<<<-mm word shift 32)))

;; ### >>>
;; Circular right shift
;;
;; Shift a 32-bit word right by <em>shift</em> bits, shifting
;; the rightmost bits into the leftmost positions.
;;
;;     (>>> 0x12345678 8)
;;
;; evaluates to
;;
;; > 0x78123456
(defn >>>
  ([word shift bits]
   (<<< word (minv-shift shift bits)))
  ([word shift]
   (>>> word shift 32)))

(defn- ^{:doc "Shift a BigInteger x right by n bits."} shift-right
  [x n]
  (.shiftRight x n))

(defn- ^{:doc "Convert a BigInt to a vector of byte values."} bi->bv
  [x]
  (let [x (.toBigInteger x)
        mask (BigInteger. "FF" 16)]
    (mapv #(.and (shift-right x %) mask) (range 56 -1 -8))))

(defn ^{:doc "Convert a value to a vector of byte values."} x->bv
  [x]
  (if (instance? clojure.lang.BigInt x)
    (bi->bv x)
    (mapv #(bit-and (bit-shift-right x %) 0xFF) (range 56 -1 -8))))

(defn ^{:doc "32-bit left shift"}
  bsl32 [x n]
  (bit-and (bit-shift-left x n) mask32))

(defn ^{:doc "32-bit right shift"}
  bsr32 [x n]
  (bit-and (bit-shift-right x n) mask32))
