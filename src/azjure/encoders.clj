(ns ^{:author "Jason Ozias"}
    azjure.encoders
  (:require [azjure.libbyte :refer [word-bytes]]
            [clojure.string :as str]))

(def maskv [63 4032 258048 16515072])
(def b64-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(def b64url-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(defn ^{:added "0.2.0"} l->hex
  "Convert a Long (0-255) to a 2-digit hex string.

  Note that in Clojure numbers are Longs by default and must be converted via
  .intValue to an Integer to convert to a hex string

  (l->hex 5) => \"05\"
  (l->hex 204) => \"cc\""
  [^Long l]
  (let [val (Integer/toHexString (.intValue l))]
    (if (= 1 (count val))
      (str "0" val)
      val)))

(defn ^{:added "0.2.0"} hex->l
  "Convert a hex string into a Long"
  [hex]
  (Long/parseLong hex 16))

(defn ^{:added "0.2.0"} every-byte?
  "Evaluates to true if every value in a sequence is between 0 and 255
  inclusive"
  [s]
  (every? true? (map #(and (>= % 0) (<= % 255)) s)))

(defn ^{:added "0.2.0"} bv->hex
  "Convert a vector of bytes (0-255) into a hex string."
  [v]
  (if (every-byte? v)
    (->> v (map l->hex) (apply str))))

(defn ^{:added "0.2.0"} hex->bv
  "Convert a string of hex values into a vector of byte values (0-255)"
  [hex]
  (->> hex
       (partition-all 2)
       (map (partial apply str))
       (map hex->l)
       vec))

(defn ^{:added "0.2.0"} bv->str
  "Convert a vector of bytes to a string"
  [bv]
  (str/join (map char bv)))

(defn ^{:added "0.2.0"} str->bv
  "Convert a string to a vector of bytes"
  [^String str]
  (vec (.getBytes str)))

(defn- mask6 [l idx]
  (bit-shift-right (bit-and l (nth maskv idx)) (* idx 6)))

(defn- b64-encode [sfn l alphabet]
  (fn [v]
    (->> (mapv mask6 (repeat (sfn v)) (range l))
         (reverse)
         (mapv #(nth alphabet %)))))

(defn- bytes->6bits [v l]
  (let [upper (* 8 (dec l))]
    (reduce bit-or
            (map #(bit-shift-left (nth v %1) %2)
                 (range l) (range upper -1 -8)))))

(defn- b64-encode-bytes [alphabet]
  (fn [v]
    {:pre [(< (count v) 4)
           (pos? (count v))]}
    (let [l (count v)
          shiftfn (condp = l
                    1 #(bit-shift-left % 4)
                    2 #(bit-shift-left % 2)
                    3 identity)]
      (into ((b64-encode shiftfn (inc l) alphabet) (bytes->6bits v l))
            (repeat (- 3 l) \=)))))

(defn- bv->base64x [bv alphabet]
  (->> (partition-all 3 bv)
       (mapv (b64-encode-bytes alphabet))
       (reduce into)
       (apply str)))

(defn- decode-shift [v]
  (map bit-shift-left v (range 18 (dec (* 6 (- 4 (count v)))) -6)))

(defn- base64x->bv [s ^String alphabet]
  (let [v (map #(.indexOf alphabet (str %)) s)]
    (->> (partition 4 v)
         (map #(remove (fn [x] (= -1 x)) %))
         (map decode-shift)
         (map (partial apply bit-xor))
         (mapv word-bytes)
         (map rest)
         (map vec)
         (reduce into))))

(defn ^{:added "0.2.0"} bv->base64
  "Convert a vector of bytes to a Base64 string"
  [bv]
  (bv->base64x bv b64-alphabet))

(defn ^{:added "0.2.0"} base64->bv
  "Convert a Base64 string to a vector of bytes"
  [s]
  (base64x->bv s b64-alphabet))

(defn ^{:added "0.2.0"} bv->base64url
  "Convert a vector of bytes to a Base64 url safe string"
  [bv]
  (bv->base64x bv b64url-alphabet))

(defn ^{:added "0.2.0"} base64url->bv
  "Convert a Base64 url safe string to a vector of bytes"
  [s]
  (base64x->bv s b64url-alphabet))

(defmulti encryption-output-encoder :eoe)
(defmethod encryption-output-encoder :str [_ bv] (bv->str bv))
(defmethod encryption-output-encoder :hex [_ bv] (bv->hex bv))
(defmethod encryption-output-encoder :base64 [_ bv] (bv->base64 bv))
(defmethod encryption-output-encoder :base64url [_ bv] (bv->base64url bv))
(defmethod encryption-output-encoder :default [_ bv] bv)

(defmulti decryption-output-encoder :doe)
(defmethod decryption-output-encoder :str [_ bv] (bv->str bv))
(defmethod decryption-output-encoder :hex [_ bv] (bv->hex bv))
(defmethod decryption-output-encoder :base64 [_ bv] (bv->base64 bv))
(defmethod decryption-output-encoder :base64url [_ bv] (bv->base64url bv))
(defmethod decryption-output-encoder :default [_ bv] bv)

(defmulti encryption-input-decoder :eid)
(defmethod encryption-input-decoder :str [_ s] (str->bv s))
(defmethod encryption-input-decoder :hex [_ s] (hex->bv s))
(defmethod encryption-input-decoder :base64 [_ s] (base64->bv s))
(defmethod encryption-input-decoder :base64url [_ s] (base64url->bv s))
(defmethod encryption-input-decoder :default [_ bv] bv)

(defmulti decryption-input-decoder :did)
(defmethod decryption-input-decoder :str [_ s] (str->bv s))
(defmethod decryption-input-decoder :hex [_ s] (hex->bv s))
(defmethod encryption-input-decoder :base64 [_ s] (base64->bv s))
(defmethod encryption-input-decoder :base64url [_ s] (base64url->bv s))
(defmethod decryption-input-decoder :default [_ bv] bv)