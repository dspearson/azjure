(ns azjure.encoders
  "## Encoders

  Various encoding/decoding functions.

  The currently supported encoding/decoding keywords for use in the
  configuration map are:

    :str       - ASCII character encoding
    :hex       - hex encoding
    :base16    - Base16 encoding (similar to hex but
                 all uppercase letters)
    :base32    - Base32 encoding
    :base32hex - Base32 encoding with the hex alphabet
    :base64    - Base64 encoding
    :base64url - Base64 encoding with the URL safe
                 alphabet

Note that if no encoding/decoding keys are supplied in the configuration map
bytes vectors are assumed as the default input/output type."
  {:author "Jason Ozias"}
  (:require [azjure.libbyte :refer :all]
            [clojure.string :as str])
  (:import (clojure.lang BigInt)))

(def ^{:private true
       :added   "0.2.0"}
  mask5
  "#### mask5
  Mask values for base32 encoding"
  [0x000000001f 0x00000003e0 0x0000007c00 0x00000f8000
   0x0001f00000 0x003e000000 0x07c0000000 0xf800000000])

(def ^{:private true
       :added   "0.2.0"}
  b32-alphabet
  "#### b32-alphabet
  The base32 alphabet string"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

(def ^{:private true
       :added   "0.2.0"}
  b32hex-alphabet
  "#### b32hex-alphabet
  The base32hex alphabet string"
  "0123456789ABCDEFGHIJKLMNOPQRSTUV")

(def ^{:private true
       :added   "0.2.0"}
  mask6
  "#### mask6
  mask values for base64 encoding"
  [0x00003f 0x000fc0 0x03f000 0xfc0000])

(def ^{:private true
       :added   "0.2.0"}
  b64-alphabet
  "#### b64-alphabet
  The base64 alphabet string"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(def ^{:private true
       :added   "0.2.0"}
  b64url-alphabet
  "#### base64url
  The base64url alphabet string"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(defmulti x->hex
          "### x->hex
  Convert an unsigned byte value x (0-255) to a 2-digit hex string.

  Values between 0-9 are padded with a `0` to 2 characters.

    (x->hex 5) => \"05\"
    (x->hex 204) => \"cc\""
          {:added "0.2.0"}
          class)

(defmethod x->hex Integer [x]
  {:pre [(>= x 0) (<= x 255)]}
  (let [val (Integer/toHexString x)]
    (if (= 1 (count val))
      (str "0" val)
      val)))

(defmethod x->hex Byte [^Byte b]
  (x->hex (.intValue b)))

(defmethod x->hex Long [^Long x]
  (x->hex (.intValue x)))

(defmethod x->hex BigInteger [^BigInteger x]
  (x->hex (.intValue x)))

(defmethod x->hex BigInt [^BigInt x]
  (x->hex (.intValue x)))

(defn hex->x
  "### hex->x
  Convert a 2 character hex string into an unsigned byte value (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s) (re-matches #"[0-9a-zA-Z]{1,2}" s)]}
  (Long/parseLong s 16))

(defn xs->hex
  "### xs->hex
  Convert a sequence of unsigned bytes (0-255) into a hex string."
  {:added "0.2.0"}
  [xs]
  {:pre [(not (nil? xs)) (every-unsigned-byte? xs)]}
  (->> xs (map x->hex) (apply str)))

(defn hex->xs
  "### hex->xs
  Convert a string of hex values into a sequence of bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (->> (reverse s)
       (partition-all 2)
       (map reverse)
       (reverse)
       (map (partial apply str))
       (map hex->x)))

(defn xs->str
  "### xs->str
  Convert a sequence of unsigned bytes (0-255) to a string"
  {:added "0.2.0"}
  [xs]
  {:pre [(not (nil? xs)) (every-unsigned-byte? xs)]}
  (str/join (map char xs)))

(defn str->xs
  "### str->xs
  Convert a string to a sequence of unsigned bytes (0-255)"
  {:added "0.2.0"}
  [^String s]
  {:pre [(string? s)]}
  (vec (.getBytes s)))

(defn- nth6bits
  "### nth6bits
  Get the value of the nth 6-bits from x.  This is used during base64 encoding
  to extract 4 values from 3 bytes (24-bits)."
  {:added "0.2.0"}
  [x n]
  {:pre [(>= x 0) (<= x 16777215)
         (>= n 0) (<= n 3)]}
  (bit-shift-right (bit-and x (nth mask6 n)) (* n 6)))

(defn- b64-encode
  "### b64-encode
  For a given shift function, length, and alphabet, encode the given sequence of
  bytes"
  {:added "0.2.0"}
  [sfn l alphabet]
  (fn [xs]
    (->> (mapv nth6bits (repeat (sfn xs)) (range l))
         (reverse)
         (mapv #(nth alphabet %)))))

(defn- b64-encode-bytes
  "### b64-encode-bytes
  For the given alphabet, encode up to 3 bytes in a sequence in base64"
  {:added "0.2.0"}
  [alphabet]
  (fn [xs]
    {:pre [(>= (count xs) 0) (<= (count xs) 3)]}
    (let [l (count xs)
          shiftfn (condp = l
                    1 #(bit-shift-left % 4)
                    2 #(bit-shift-left % 2)
                    3 identity)]
      (into ((b64-encode shiftfn (inc l) alphabet)
             (ubv->x xs))
            (repeat (- 3 l) \=)))))

(defn- xs->base64x
  "### xs->base64x
  Convert a sequence of unsigned bytes (0-255) into a base64x encoded string.
  The second argument is the base64 alphabet to use."
  {:added "0.2.0"}
  [xs alphabet]
  {:pre [(every-unsigned-byte? xs) (string? alphabet) (= 64 (count alphabet))]}
  (if (empty? xs)
    ""
    (->> (partition-all 3 xs)
         (mapv (b64-encode-bytes alphabet))
         (reduce into)
         (apply str))))

(defn- b64-decode-shift
  "### b64-decode-shift
  Bit shifting used during the decoding of a base64x encoded string"
  {:added "0.2.0"}
  [xs]
  (map bit-shift-left xs (range 18 (dec (* 6 (- 4 (count xs)))) -6)))

(defn- base64x->xs
  "### base64x->xs
  Convert a base64x string into a sequence of unsigned bytes.  The second
  argument is the base64 alphabet to use."
  {:added "0.2.0"}
  [s ^String alphabet]
  {:pre [(string? s)]}
  (if (empty? s)
    []
    (->> (map #(.indexOf alphabet (str %)) s)
         (partition 4)
         (map #(remove (fn [x] (= -1 x)) %))
         (map b64-decode-shift)
         (map (partial apply bit-xor))
         (mapv word-bytes)
         (map rest)
         (map vec)
         (reduce into)
         (take-while #(not (zero? %)))
         (vec))))

(defn xs->base64
  "### xs->base64
  Convert a sequence of unsigned bytes (0-255) to a Base64 string"
  {:added "0.2.0"}
  [xs]
  {:pre [(not (nil? xs))]}
  (xs->base64x xs b64-alphabet))

(defn base64->xs
  "### base64-xs
  Convert a Base64 string to a vector of unsigned bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (base64x->xs s b64-alphabet))

(defn xs->base64url
  "### xs->base64url
  Convert a sequence of unsigned bytes (0-255) to a Base64 url safe string"
  {:added "0.2.0"}
  [xs]
  {:pre [(not (nil? xs))]}
  (xs->base64x xs b64url-alphabet))

(defn base64url->xs
  "### base64url->xs
  Convert a Base64 url safe string to a sequence of unsigned bytes (0-255)"
  {:added "0.2.0"}
  [s]
  (base64x->xs s b64url-alphabet))

(defn- nth5bits
  "### nth5bits
  Get the value of the nth 5-bits from *xs*.  This is used during base32
  encoding to extract 8 values from 5 bytes (40-bits)."
  {:added "0.2.0"}
  [xs n]
  {:pre [(>= xs 0) (<= xs 1099511627775)
         (>= n 0) (<= n 8)]}
  (bit-shift-right (bit-and xs (nth mask5 n)) (* n 5)))

(defn- b32-encode
  "### b32-encode
  For a given shift function, length, and alphabet, encode the given sequence
  of bytes"
  {:added "0.2.0"}
  [l alphabet]
  (fn [xs]
    (->> (mapv nth5bits (repeat xs) (range l))
         (reverse)
         (mapv #(nth alphabet %)))))

(defn- pad-count
  "### pad-count
  Generate the pad count for Base32 encoding based on the length of the last
  set of bytes."
  {:added "0.2.0"}
  [l]
  (/ (- 40 (.intValue ^Double (* (Math/ceil (/ (* 8 l) 5.0)) 5))) 5))

(defn- b32-encode-bytes
  "### b32-encode-bytes
  For the given alphabet, encode up to 5 bytes in a sequence in base32"
  {:added "0.2.0"}
  [alphabet]
  (fn [xs]
    {:pre [(>= (count xs) 0) (<= (count xs) 5)]}
    (let [l (count xs)
          [shiftfn b] (condp = l
                        1 [(fn [x] (bit-shift-left x 2)) 2]
                        2 [(fn [x] (bit-shift-left x 4)) 4]
                        3 [(fn [x] (bit-shift-left x 1)) 5]
                        4 [(fn [x] (bit-shift-left x 3)) 7]
                        5 [identity 8])]
      (into ((b32-encode b alphabet)
             (shiftfn (ubv->x xs)))
            (repeat (pad-count l) \=)))))

(defn- xs->base32x
  "### xs->base32x
  Convert a sequence of unsigned bytes (0-255) into a base32x encoded string.
  The second argument is the base32 alphabet to use."
  {:added "0.2.0"}
  [xs alphabet]
  {:pre [(vector? xs) (every-unsigned-byte? xs)
         (string? alphabet) (= 32 (count alphabet))]}
  (if (empty? xs)
    ""
    (->> (partition-all 5 xs)
         (mapv (b32-encode-bytes alphabet))
         (reduce into)
         (apply str))))

(defn- b32-decode-shift
  "### b32-decode-shift
  Bit shifting used during the decoding of a base32x encoded string"
  {:added "0.2.0"}
  [x]
  (map bit-shift-left x (range 35 (dec (* 5 (- 8 (count x)))) -5)))

(defn- base32x->xs
  "### base32x->xs
  Convert a Base32 string to a sequence of unsigned bytes (0-255)"
  {:added "0.2.0"}
  [s alphabet]
  (->> (map #(.indexOf ^String alphabet (str %)) s)
       (partition 8)
       (map #(remove (fn [x] (= -1 x)) %))
       (map b32-decode-shift)
       (mapv (partial apply bit-xor))
       (mapv x->ubv)
       (reduce into)
       (take-while #(not (zero? %)))
       (vec)))

(defn xs->base32
  "### xs->base32
  Convert a vector of unsigned bytes (0-255) to a Base32 string"
  {:added "0.2.0"}
  [xs]
  (xs->base32x xs b32-alphabet))

(defn base32->xs
  "### base32->xs
  Convert a Base32 string to a sequence of unsigned bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (base32x->xs s b32-alphabet))

(defn xs->base32hex
  "### xs->base32hex
  Convert a sequence of unsigned bytes (0-255) to a Base32-Hex string"
  {:added "0.2.0"}
  [xs]
  (xs->base32x xs b32hex-alphabet))

(defn base32hex->xs
  "### base32hex->xs
  Convert a Base32-Hex string to a sequence of unsigned bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (base32x->xs s b32hex-alphabet))

(defn xs->base16
  "### xs->base16
  Convert a sequence of unsigned bytes (0-255) to a Base16 string."
  {:added "0.2.0"}
  [xs]
  (.toUpperCase ^String (xs->hex xs)))

(defn base16->xs
  "### base16->xs
  Convert a Base16 string to a sequence of unsigned bytes (0-255)."
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (hex->xs s))

(defn- encoder-dispatcher
  "### encode-dispatcher
  Dispatcher for the output encoders"
  {:added "0.2.0"}
  [m _ & {:keys [encryption] :or {encryption true}}]
  (if encryption (:eoe m) (:doe m)))

(defmulti output-encoder
          "### output-encoder
  Output encoding"
          {:added "0.2.0"}
          encoder-dispatcher)

(defmethod output-encoder :str [_ bv & _] (xs->str bv))
(defmethod output-encoder :hex [_ bv & _] (xs->hex bv))
(defmethod output-encoder :base64 [_ bv & _] (xs->base64 bv))
(defmethod output-encoder :base64url [_ bv & _] (xs->base64url bv))
(defmethod output-encoder :base32 [_ bv & _] (xs->base32 bv))
(defmethod output-encoder :base32hex [_ bv & _] (xs->base32hex bv))
(defmethod output-encoder :base16 [_ bv & _] (xs->base16 bv))
(defmethod output-encoder :default [_ bv & _] bv)

(defn- decoder-dispatcher
  "### decoder-dispatcher
  Dispatcher for the input decoders"
  {:added "0.2.0"}
  [m _ & {:keys [encryption] :or {encryption true}}]
  (if encryption (:eid m) (:did m)))

(defmulti input-decoder
          "### input-decoder
  Input decoding"
          {:added "0.2.0"}
          decoder-dispatcher)

(defmethod input-decoder :str [_ s & _] (str->xs s))
(defmethod input-decoder :hex [_ s & _] (hex->xs s))
(defmethod input-decoder :base64 [_ s & _] (base64->xs s))
(defmethod input-decoder :base64url [_ s & _] (base64url->xs s))
(defmethod input-decoder :base32 [_ s & _] (base32->xs s))
(defmethod input-decoder :base32hex [_ s & _] (base32hex->xs s))
(defmethod input-decoder :base16 [_ s & _] (base16->xs s))
(defmethod input-decoder :default [_ bv & _] bv)