(ns azjure.encoders
  {:author "Jason Ozias"}
  (:require [azjure.libbyte :refer :all]
            [clojure.string :as str]))

(def ^{:private true :doc "mask values for base64 encoding"} maskv
  [63 4032 258048 16515072])
(def ^{:private true :doc "The base64 alphabet string"} b64-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(def ^{:private true :doc "The base64url alphabet string"} b64url-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(defn x->hex
  "Convert a byte value x (0-255) to a 2-digit hex string.

  Values between 0-9 are padded with a 0 to 2 characters.

  (x->hex 5) => \"05\"
  (x->hex 204) => \"cc\""
  {:added "0.2.0"}
  [^Long x]
  (let [val (Integer/toHexString (.intValue x))]
    (if (= 1 (count val))
      (str "0" val)
      val)))

(defn hex->x
  "Convert a 2 character hex string into a byte value (0-255)"
  {:added "0.2.0"}
  [s]
  {:pre [(= 2 (count s))]}
  (Long/parseLong s 16))

(defn v->hex
  "Convert a vector of bytes (0-255) into a hex string."
  {:added "0.2.0"}
  [v]
  {:pre [(every-byte? v)]}
  (->> v (map x->hex) (apply str)))

(defn hex->v
  "Convert a string of hex values into a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s]
  (->> s
       (partition-all 2)
       (map (partial apply str))
       (map hex->x)
       vec))

(defn v->str
  "Convert a vector of bytes (0-255) to a string"
  {:added "0.2.0"}
  [v]
  {:pre [(every-byte? v)]}
  (str/join (map char v)))

(defn str->v
  "Convert a string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [^String str]
  (vec (.getBytes str)))

(defn- nth6bits
  "Get the value of the nth 6-bits from x.  This is used during base64 encoding
  to extract 4 values from 3 bytes (24-bits)."
  {:added "0.2.0"}
  [x n]
  {:pre [(< x 16777216)
         (>= x 0)]}
  (bit-shift-right (bit-and x (nth maskv n)) (* n 6)))

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
    {:pre [(< (count v) 4)
           (pos? (count v))]}
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
  {:added "0.2.0"}
  [v alphabet]
  {:pre [(every-byte? v)]}
  (->> (partition-all 3 v)
       (mapv (b64-encode-bytes alphabet))
       (reduce into)
       (apply str)))

(defn- decode-shift
  "Bit shifting used during the decoding of a base64x encoded string"
  {:added "0.2.0"}
  [x]
  (map bit-shift-left x (range 18 (dec (* 6 (- 4 (count x)))) -6)))

(defn- base64x->v
  "Convert a base64x string into a vector of bytes.  The second argument is the
  base64 alphabet to use."
  {:added "0.2.0"}
  [s ^String alphabet]
  (let [v (map #(.indexOf alphabet (str %)) s)]
    (->> (partition 4 v)
         (map #(remove (fn [x] (= -1 x)) %))
         (map decode-shift)
         (map (partial apply bit-xor))
         (mapv word-bytes)
         (map rest)
         (map vec)
         (reduce into))))

(defn v->base64
  "Convert a vector of bytes (0-255) to a Base64 string"
  {:added "0.2.0"}
  [v]
  (v->base64x v b64-alphabet))

(defn base64->v
  "Convert a Base64 string to a vector of bytes (0-255)"
  {:added "0.2.0"}
  [s]
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
(defmethod input-decoder :default [_ bv & _] bv)