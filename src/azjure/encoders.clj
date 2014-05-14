(ns azjure.encoders
  {:author "Jason Ozias"}
  (:require [azjure.libbyte :refer :all]
            [clojure.string :as str])
  (:import (clojure.lang BigInt)))

(def ^{:private true :doc "Mask values for base32 encoding"} mask5
  [31 992 31744 1015808 32505856 1040187392 33285996544 1065151889408])
(def ^{:private true :doc "The base32 alphabet string"} b32-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
(def ^{:private true :doc "The base32hex alphabet string"} b32hex-alphabet
  "0123456789ABCDEFGHIJKLMNOPQRSTUV")
(def ^{:private true :doc "mask values for base64 encoding"} mask6
  [63 4032 258048 16515072])
(def ^{:private true :doc "The base64 alphabet string"} b64-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(def ^{:private true :doc "The base64url alphabet string"} b64url-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(defmulti x->hex "Convert a byte value x (0-255) to a 2-digit hex string.

  Values between 0-9 are padded with a 0 to 2 characters.

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
  "Convert a 2 character hex string into a byte value (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s) (re-matches #"[0-9a-zA-Z]{1,2}" s)]}
  (Long/parseLong s 16))

(defn v->hex
  "Convert a vector of bytes (0-255) into a hex string."
  {:added "0.2.0"}
  [v]
  {:pre [(vector? v) (every-byte? v)]}
  (->> v (map x->hex) (apply str)))

(defn hex->v
  "Convert a string of hex values into a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (->> s
       (reverse)
       (partition-all 2)
       (map reverse)
       (reverse)
       (map (partial apply str))
       (map hex->x)
       vec))

(defn v->str
  "Convert a vector of bytes (0-255) to a string"
  {:added "0.2.0"}
  [v]
  {:pre [(vector? v) (every-byte? v)]}
  (str/join (map char v)))

(defn str->v
  "Convert a string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [^String s]
  {:pre [(string? s)]}
  (vec (.getBytes s)))

(defn- nth6bits
  "Get the value of the nth 6-bits from x.  This is used during base64 encoding
  to extract 4 values from 3 bytes (24-bits)."
  {:added    "0.2.0"
   :testable true}
  [x n]
  {:pre [(>= x 0) (<= x 16777215)
         (>= n 0) (<= n 3)]}
  (bit-shift-right (bit-and x (nth mask6 n)) (* n 6)))

(defn- b64-encode
  "For a given shift function, length, and alphabet, encode the given vector of
  bytes"
  {:added "0.2.0"}
  [sfn l alphabet]
  (fn [v]
    (->> (mapv nth6bits (repeat (sfn v)) (range l))
         (reverse)
         (mapv #(nth alphabet %)))))

(defn- b64-encode-bytes
  "For the given alphabet, encode up to 3 bytes in a vector in base64"
  {:added "0.2.0"}
  [alphabet]
  (fn [v]
    {:pre [(>= (count v) 0) (<= (count v) 3)]}
    (let [l (count v)
          shiftfn (condp = l
                    1 #(bit-shift-left % 4)
                    2 #(bit-shift-left % 2)
                    3 identity)]
      (into ((b64-encode shiftfn (inc l) alphabet)
             (.longValue ^BigInteger (bytes->val v)))
            (repeat (- 3 l) \=)))))

(defn- v->base64x
  "Convert a vector of bytes (0-255) into a base64x encoded string.  The second
  argument is the base64 alphabet to use."
  {:added    "0.2.0"
   :testable true}
  [v alphabet]
  {:pre [(vector? v) (every-byte? v)
         (string? alphabet) (= 64 (count alphabet))]}
  (if (empty? v)
    ""
    (->> (partition-all 3 v)
         (mapv (b64-encode-bytes alphabet))
         (reduce into)
         (apply str))))

(defn- b64-decode-shift
  "Bit shifting used during the decoding of a base64x encoded string"
  {:added    "0.2.0"
   :testable true}
  [xs]
  (map bit-shift-left xs (range 18 (dec (* 6 (- 4 (count xs)))) -6)))

(defn- base64x->v
  "Convert a base64x string into a vector of bytes.  The second argument is the
  base64 alphabet to use."
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

(defn v->base64
  "Convert a vector of bytes (0-255) to a Base64 string"
  {:added "0.2.0"}
  [v]
  {:pre [(vector? v)]}
  (v->base64x v b64-alphabet))

(defn base64->v
  "Convert a Base64 string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (base64x->v s b64-alphabet))

(defn v->base64url
  "Convert a vector of bytes (0-255) to a Base64 url safe string"
  {:added "0.2.0"}
  [v]
  (v->base64x v b64url-alphabet))

(defn base64url->v
  "Convert a Base64 url safe string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s]
  (base64x->v s b64url-alphabet))

(defn- nth5bits
  "Get the value of the nth 5-bits from x.  This is used during base32 encoding
  to extract 8 values from 5 bytes (40-bits)."
  {:added    "0.2.0"
   :testable true}
  [x n]
  {:pre [(>= x 0) (<= x 1099511627775)
         (>= n 0) (<= n 8)]}
  (bit-shift-right (bit-and x (nth mask5 n)) (* n 5)))

(defn- b32-encode
  "For a given shift function, length, and alphabet, encode the given vector of
  bytes"
  {:added "0.2.0"}
  [l alphabet]
  (fn [v]
    (->> (mapv nth5bits (repeat v) (range l))
         (reverse)
         (mapv #(nth alphabet %)))))

(defn- pad-count
  "Generate the pad count for Base32 encoding based on the length of the last
  set of bytes."
  {:added    "0.2.0"
   :testable true}
  [l]
  (/ (- 40 (.intValue ^Double (* (Math/ceil (/ (* 8 l) 5.0)) 5))) 5))

(defn- b32-encode-bytes
  "For the given alphabet, encode up to 5 bytes in a vector in base32"
  {:added "0.2.0"}
  [alphabet]
  (fn [v]
    {:pre [(>= (count v) 0) (<= (count v) 5)]}
    (let [l (count v)
          [shiftfn b] (condp = l
                        1 [(fn [x] (bit-shift-left x 2)) 2]
                        2 [(fn [x] (bit-shift-left x 4)) 4]
                        3 [(fn [x] (bit-shift-left x 1)) 5]
                        4 [(fn [x] (bit-shift-left x 3)) 7]
                        5 [identity 8])]
      (into ((b32-encode b alphabet)
             (shiftfn (.longValue ^BigInteger (bytes->val v))))
            (repeat (pad-count l) \=)))))

(defn- v->base32x
  "Convert a vector of bytes (0-255) into a base32x encoded string.  The second
  argument is the base32 alphabet to use."
  {:added    "0.2.0"
   :testable true}
  [v alphabet]
  {:pre [(vector? v) (every-byte? v)
         (string? alphabet) (= 32 (count alphabet))]}
  (if (empty? v)
    ""
    (->> (partition-all 5 v)
         (mapv (b32-encode-bytes alphabet))
         (reduce into)
         (apply str))))

(defn- b32-decode-shift
  "Bit shifting used during the decoding of a base32x encoded string"
  {:added "0.2.0"}
  [x]
  (map bit-shift-left x (range 35 (dec (* 5 (- 8 (count x)))) -5)))

(defn- base32x->v
  "Convert a Base32 string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s alphabet]
  (->> (map #(.indexOf ^String alphabet (str %)) s)
       (partition 8)
       (map #(remove (fn [x] (= -1 x)) %))
       (map b32-decode-shift)
       (mapv (partial apply bit-xor))
       (mapv val->bytes)
       (reduce into)
       (take-while #(not (zero? %)))
       (vec)))

(defn v->base32
  "Convert a vector of bytes (0-255) to a Base32 string"
  {:added "0.2.0"}
  [v]
  {:pre [(vector? v)]}
  (v->base32x v b32-alphabet))

(defn v->base32hex
  "Convert a vector of bytes (0-255) to a Base32-Hex string"
  {:added "0.2.0"}
  [v]
  {:pre [(vector? v)]}
  (v->base32x v b32hex-alphabet))

(defn base32->v
  "Convert a Base32 string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (base32x->v s b32-alphabet))

(defn base32hex->v
  "Convert a Base32-Hex string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(string? s)]}
  (base32x->v s b32hex-alphabet))

(defn v->base16
  "Convert a vector of bytes (0-255) to a Base16 string."
  [v]
  {:pre [(vector? v)]}
  (.toUpperCase ^String (v->hex v)))

(defn base16->v
  "Convert a Base16 string to a vector of bytes (0-255)."
  [s]
  {:pre [(string? s)]}
  (hex->v s))

(defn- encoder-dispatcher
  "Dispatcher for the output encoders"
  [m _ & {:keys [encryption] :or {encryption true}}]
  (if encryption (:eoe m) (:doe m)))

(defmulti output-encoder
          "Output encoding"
          {:added "0.2.0"}
          encoder-dispatcher)

(defmethod output-encoder :str [_ bv & _] (v->str bv))
(defmethod output-encoder :hex [_ bv & _] (v->hex bv))
(defmethod output-encoder :base64 [_ bv & _] (v->base64 bv))
(defmethod output-encoder :base64url [_ bv & _] (v->base64url bv))
(defmethod output-encoder :base32 [_ bv & _] (v->base32 bv))
(defmethod output-encoder :base32hex [_ bv & _] (v->base32hex bv))
(defmethod output-encoder :base16 [_ bv & _] (v->base16 bv))
(defmethod output-encoder :default [_ bv & _] bv)

(defn- decoder-dispatcher
  "Dispatcher for the input decoders"
  [m _ & {:keys [encryption] :or {encryption true}}]
  (if encryption (:eid m) (:did m)))

(defmulti input-decoder
          "Input decoding"
          {:added "0.2.0"}
          decoder-dispatcher)

(defmethod input-decoder :str [_ s & _] (str->v s))
(defmethod input-decoder :hex [_ s & _] (hex->v s))
(defmethod input-decoder :base64 [_ s & _] (base64->v s))
(defmethod input-decoder :base64url [_ s & _] (base64url->v s))
(defmethod input-decoder :base32 [_ s & _] (base32->v s))
(defmethod input-decoder :base32hex [_ s & _] (base32hex->v s))
(defmethod input-decoder :base16 [_ s & _] (base16->v s))
(defmethod input-decoder :default [_ bv & _] bv)