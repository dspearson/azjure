(ns azjure.libbyte
  {:author "Jason Ozias"}
  (:require [clojure.math.numeric-tower :refer [expt]])
  (:import (clojure.lang BigInt)))

(def ^{:doc "32-bit mask"} mask32 0xFFFFFFFF)

(defn every-byte?
  "Evaluates to true if every value in a sequence is between 0 and 255
  inclusive"
  [s]
  {:added "0.2.0"}
  (every? true? (map #(and (>= % 0) (<= % 255)) s)))

(defmulti last-byte
          "Get the last byte from a value"
          {:arglists '([x])
           :added    "0.2.0"}
          class)

(defmethod last-byte BigInt [^BigInt x]
  (.longValue (.and (.toBigInteger x) (.toBigInteger (bigint 0xff)))))

(defmethod last-byte BigInteger [^BigInteger x]
  (.longValue (.and x (.toBigInteger (bigint 0xff)))))

(defmethod last-byte Long [x]
  (bit-and 0xff x))

(defn bit-shift-right-big
  "bitwise shift a BigInteger x right y bits"
  {:added "0.2.0"}
  [^BigInteger x y]
  (.shiftRight x y))

(defn bit-shift-left-big
  "bitwise shift a BigInteger x left y bits"
  {:added "0.2.0"}
  [^BigInteger x y]
  (.shiftLeft x y))

(defn or-big
  "bitwise or BigInteger x and BigInteger y"
  {:added "0.2.0"}
  [^BigInteger x ^BigInteger y]
  (.or x y))

(defn bytes->val
  "Convert a vector of bytes (0-255) to a value"
  {:added "0.2.0"}
  [v]
  {:pre [(every-byte? v)]}
  (let [l (count v)]
    (reduce or-big
            (map #(bit-shift-left-big (.toBigInteger (bigint (nth v %1))) %2)
                 (range l)
                 (range (* 8 (dec l)) -1 -8)))))

(defmulti val->bytes
          "Convert a value to a vector of bytes (0-255)"
          {:arglists '([x])
           :added    "0.2.0"}
          class)

(defn- val->bytesfn
  "Shift x right 8-bits and accumulate the last byte value in a vector."
  {:added "0.2.0"}
  [x sfn]
  (loop [curr x
         acc []]
    (cond (and (zero? curr) (empty? acc)) [0]
          (zero? curr) (vec (reverse acc))
          :else (recur (sfn curr 8) (conj acc (last-byte curr))))))

(defmethod val->bytes BigInteger [^BigInteger x]
  (val->bytesfn x bit-shift-right-big))

(defmethod val->bytes BigInt [^BigInt x]
  (val->bytesfn (.toBigInteger x) bit-shift-right-big))

(defmethod val->bytes Long [x]
  (val->bytesfn x unsigned-bit-shift-right))

(defmulti xor
          "bitwise xor for different classes"
          {:arglists '([x y])
           :added    "0.2.0"}
          (fn [x _] (class x)))

(defmethod xor Long [x y] (bit-xor x y))
(defmethod xor BigInteger [^BigInteger x y] (.xor x (.toBigInteger (bigint y))))

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

(defn shift-dispatch [word _ bits]
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
        (.and (.shiftLeft ^BigInteger biw sft) mask)
        (.shiftRight ^BigInteger biw (minv-shift sft bits))))))

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
  [^BigInteger x n]
  (.shiftRight x n))

(defn- ^{:doc "Convert a BigInt to a vector of byte values."} bi->bv
  [^BigInt x]
  (let [x (.toBigInteger x)
        mask (BigInteger. "FF" 16)]
    (mapv #(.and ^BigInteger (shift-right x %) mask) (range 56 -1 -8))))

(defn ^{:doc "Convert a value to a vector of byte values."} x->bv
  [x]
  (if (instance? BigInt x)
    (bi->bv x)
    (mapv #(bit-and (bit-shift-right x %) 0xFF) (range 56 -1 -8))))

(defn ^{:doc "32-bit left shift"}
  bsl32 [x n]
  (bit-and (bit-shift-left x n) mask32))

(defn ^{:doc "32-bit right shift"}
  bsr32 [x n]
  (bit-and (bit-shift-right x n) mask32))
