(ns azjure.libbyte
  "## libbyte
  Bitwise operations library"
  {:author "Jason Ozias"}
  (:require [clojure.math.numeric-tower :refer [expt]])
  (:import (clojure.lang BigInt)))

(def ^{:added "0.2.0"}
  mask32
  "### mask32
  32-bit mask"
  0xFFFFFFFF)

(defn every-bit?
  "### every-bit?
  Evaluates to true if every value in a sequence `xs` is a 0 or a 1"
  {:added "0.2.0"}
  [xs]
  (every? true? (map #(or (zero? %) (= 1 %)) xs)))

(defn every-byte?
  "### every-byte?
  Evaluates to true if every value in a sequence is between 0 and 255
  inclusive"
  {:added "0.2.0"}
  [xs]
  (every? true? (map #(and (>= % 0) (<= % 255)) xs)))

(defmulti last-byte
          "###last-byte
  Get the last byte from a value"
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
  "### bit-shift-right-big
  bitwise shift a BigInteger x right y bits"
  {:added "0.2.0"}
  [^BigInteger x y]
  (.shiftRight x y))

(defn bit-shift-left-big
  "### bit-shift-left-big
  bitwise shift a BigInteger x left y bits"
  {:added "0.2.0"}
  [^BigInteger x y]
  (.shiftLeft x y))

(defn bit-or-big
  "### bitwise-or-big
  bitwise or BigInteger x and BigInteger y"
  {:added "0.2.0"}
  [^BigInteger x ^BigInteger y]
  (.or x y))

(defn- long-or-bigint?
  "### long-or-bigint?
  Determine which set of bit math functions to use.

  Java Long primitive types can only hold non-negative values between 0 and
  2<sup>63</sup>-1 inclusive.  The largest vector of unsigned bytes in
  big-endian format (MSB is leftmost) that is supported by Long math is
  [127 x x x x x x x]. If the unsigned bytes are little-endian format (MSB is
  rightmost), the last byte checked against 127 instead of the first.  Note that
  longer vectors may still be processed as Longs if they are filled with 0's"
  {:added "0.2.0"}
  [ubv le]
  (let [l (count ubv)
        fns {:long   [bit-or bit-shift-left]
             :bigint [bit-or-big
                      #(bit-shift-left-big (BigInteger/valueOf %1) %2)]}]
    (cond
      (< l 8) (:long fns)
      (= l 8) (if (< (if-not le (first ubv) (last ubv)) 128)
                (:long fns)
                (:bigint fns))
      (> l 8) (let [nonzeros (remove zero?
                                     (if le (subvec ubv 8) (drop-last 8 ubv)))]
                (if (seq nonzeros)
                  (:bigint fns)
                  (:long fns))))))

(defn ubv->x
  "### ubv->x
  Convert a vector of unsigned bytes (0-255) to a value"
  {:added "0.2.0"}
  [xv & {:keys [le]}]
  {:pre [(every-byte? xv)]}
  (let [l (count xv)
        [orfn shiftfn] (long-or-bigint? xv le)]
    (->> (if le (range 0 (* 8 l) 8) (range (* 8 (dec l)) -1 -8))
         (map shiftfn xv)
         (reduce orfn))))

(defmulti x->ubv
          "### x->ubv
  Convert a value to a vector of bytes (0-255)"
          {:arglists '([x])
           :added    "0.2.0"}
          class)

(defn- x->ubvfn
  "### x->ubvfn
  Shift x right 8-bits and accumulate the last byte value in a vector."
  {:added "0.2.0"}
  [x sfn]
  (loop [curr x
         acc []]
    (cond (and (zero? curr) (empty? acc)) [0]
          (zero? curr) (vec (reverse acc))
          :else (recur (sfn curr 8) (conj acc (last-byte curr))))))

(defmethod x->ubv BigInteger [^BigInteger x]
  (x->ubvfn x bit-shift-right-big))

(defmethod x->ubv BigInt [^BigInt x]
  (x->ubvfn (.toBigInteger x) bit-shift-right-big))

(defmethod x->ubv Long [x]
  (x->ubvfn x unsigned-bit-shift-right))

(defn- as-xword
  "### as-xword
  Take a sequence of up to x-bytes and convert them into a sequence of exactly
  x-bytes."
  {:added "0.2.0"}
  [xs x]
  (->> (repeat (- x (count xs)) 0)
       (reduce conj (seq xs))
       (vec)))

(defn as-word
  "### as-word
  Take a sequence of up to 4-bytes and convert them into a sequence of exactly
  4-bytes (a 32-bit word)."
  {:added "0.2.0"}
  [xs]
  {:pre  [(<= (count xs) 4)]
   :post [(= 4 (count %))]}
  (as-xword xs 4))

(defn as-dword
  "### as-dword
  Take a sequence of up to 8-bytes and convert them into a sequence of exactly
  8-bytes (a 64-bit dword)."
  {:added "0.2.0"}
  [xs]
  {:pre  [(<= (count xs) 8)]
   :post [(= 8 (count %))]}
  (as-xword xs 8))

(defmulti xor
          "### xor
  bitwise xor for different classes"
          {:arglists '([x y])
           :added    "0.2.0"}
          (fn [x _] (class x)))

(defmethod xor Long [x y] (bit-xor x y))
(defmethod xor BigInteger [^BigInteger x y] (.xor x (.toBigInteger (bigint y))))

(defn indexed
  "### indexed
  Returns a lazy sequence of [index, item] pairs, where items come from 's' and
  indexes count up from zero.

    (indexed '(a b c d))  =>  ([0 a] [1 b] [2 c] [3 d])"
  {:added "0.2.0"}
  [s]
  (map vector (iterate inc 0) s))

(defn positions
  "### positions
  Returns a lazy sequence containing the positions at which pred is true for
  items in coll."
  {:added "0.2.0"}
  [pred coll]
  (for [[idx elt] (indexed coll) :when (pred elt)] idx))

(defn byte->bits
  "### byte->bits
  Convert a byte (0-255) into a vector of bits"
  {:added "0.2.0"}
  [x]
  {:pre [(>= x 0) (<= x 255)]}
  (vec (reverse (mapv #(if % 1 0) (mapv (partial bit-test x) (range 8))))))

(defn bits->byte
  "### bits->byte
  Convert a vector of bits into a byte (0-255)"
  {:added "0.2.0"}
  [v]
  {:pre [(= (count v) 8)
         (every-bit? v)]}
  (reduce bit-set 0 (positions #{1} (reverse v))))

(defn get-byte
  "### get-byte
  Get the nth byte out of the given word.  n is a value from 1 to 4 where 1
  represents the least significant byte and 4 represents the most significant
  byte

    (get-byte 0x11223344 4) => 0x11"
  {:added "0.2.0"}
  [n x]
  (let [shift (* 8 (dec n))
        sftfn (if (zero? shift) x (bit-shift-right x shift))]
    (bit-and sftfn 0xFF)))

(defn bytes-word
  "### bytes-word
  Take a vector of 4 bytes (0-255) and create a 32-bit word value. If le is
  true, the vector is assumed to be in little endian format.

    (bytes-word [0x12 0xab 0x1f 0x3b]) => 0x12ab1f3b"
  {:added "0.2.0"}
  ([v le]
   (let [rng (if le (range 0 32 8) (range 24 -1 -8))]
     (reduce bit-or (map #(bit-shift-left (nth v %1) %2) (range 4) rng))))
  ([v]
   (bytes-word v false)))

(defn bytes-dword
  "### bytes-dword
  Take a vector of 8 bytes (0-255) and create a 64-bit dword value."
  {:added "0.2.0"}
  [v]
  (apply bit-or
         (map #(bit-shift-left (nth v %1) %2)
              (range 8)
              (range 56 -1 -8))))

(defn word-bytes
  "### word-bytes
  Converts a word value to a vector of 4 bytes (0-255).  If le is true, the
  conversion is made to little endian format.

    (word-bytes 0x12ab1f3b) => [0x12 0xab 0x1f 0x3b]"
  {:added "0.2.0"}
  ([word le]
   (let [rng (if le (range 0 32 8) (range 24 -1 -8))]
     (mapv #(last-byte (bit-shift-right word %)) rng)))
  ([word]
   (word-bytes word false)))

(defn dword-bytes
  "### dword-bytes
  Converts a dword value to a vector of 8 bytes (0-255).  If le is true, the
  conversion is made to little endian format."
  {:added "0.2.0"}
  ([dword le]
   (let [rng (if le (range 0 64 8) (range 56 -1 -8))]
     (mapv #(last-byte (bit-shift-right dword %)) rng)))
  ([dword]
   (dword-bytes dword false)))

(defn reverse-bytes
  "### reverse-bytes
  Reverse the bytes in a word.

    (reverse-bytes 0x01234567) => 0x67452301"
  {:added "0.2.0"}
  [word]
  (-> #(last-byte (bit-shift-right word %1))
      (mapv (range 0 32 8))
      (bytes-word)))

(defn- inv-shift
  "### inv-shift
  Invert the shift"
  {:added "0.2.0"}
  [shift bits]
  (- bits shift))

(def ^{:doc "### minv-shfit
  Invert the shift"
       :added "0.2.0"}
  minv-shift (memoize inv-shift))

(defn- shift-dispatch
  "### shift-dispatch
  Circular left shift dispatch method"
  {:added "0.2.0"}
  [word _ bits]
  (cond
    (or (instance? BigInteger word) (> bits 32)) :a
    :else :default))

(defmulti <<<-mm
          "### <<<-mm
  Circular shift left"
          {:added "0.2.0"}
          shift-dispatch)

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
  "### <<<
  Bitwise circular shift left.  Shifts a 32-bit word left by x bits, shifting
  the leftmost bits into the rightmost positions."
  {:added "0.2.0"}
  ([word shift bits] (<<<-mm word shift bits))
  ([word shift] (<<<-mm word shift 32)))

(defn >>>
  "### >>>
  Bitwise circular shift right.  Shifts a 32-bit word right by x bits, shifting
  the rightmost bits into the leftmost positions.

    (>>> 0x12345678 8) => 0x78123456"
  {:added "0.2.0"}
  ([word shift bits]
   (<<< word (minv-shift shift bits)))
  ([word shift]
   (>>> word shift 32)))

(defn- shift-right
  "### shift-right
  Shift a BigInteger x right by n bits."
  {:added "0.2.0"}
  [^BigInteger x n]
  (.shiftRight x n))

(defn- bi->bv
  "### bi->bv
  Convert a BigInt to a vector of byte values."
  {:added "0.2.0"}
  [^BigInt x]
  (let [x (.toBigInteger x)
        mask (BigInteger. "FF" 16)]
    (mapv #(.and ^BigInteger (shift-right x %) mask) (range 56 -1 -8))))

(defn x->bv
  "### x->bv
  Convert a value to a vector of byte values."
  {:added "0.2.0"}
  [x]
  (if (instance? BigInt x)
    (bi->bv x)
    (mapv #(bit-and (bit-shift-right x %) 0xFF) (range 56 -1 -8))))

(defn bsl32
  "### bsl32
  32-bit left shift"
  {:added "0.2.0"}
  [x n]
  (bit-and (bit-shift-left x n) mask32))

(defn bsr32
  "### bsr32
  32-bit right shift"
  {:added "0.2.0"}
  [x n]
  (bit-and (bit-shift-right x n) mask32))