(ns org.ozias.cljlibs.azjure.core)

(defmulti initialize
          "Takes an initmap and assocs any additional keys needed by the
  cipher"
          {:arglists '([m])
           :added    "0.2.0"}
          :type)

(defmulti keysizes-bits
          "Evaluates to a vector of key sizes in bits supported by the cipher"
          {:arglists '([])}
          :type)

(defmulti blocksize-bits
          "Evaluates to the block size in bits supported by the block cipher"
          {:arglists '([])}
          :type)

(defmulti encrypt-block
          "Takes an initmap and a vector of byte values of the appropriate block
  size for the cipher and encrypts it.

  Evaluates to a vector of byte values."
          {:arglists '([m block])}
          :type)

(defmulti decrypt-block
          "Takes an initmap and a vector of byte values of the appropriate block
  size for the cipher and decrypts it.

  Evaluates to a vector of byte values."
          {:arglists '([m block])}
          :type)

(defmulti iv-size-bytes :type)
(defmulti keystream-size-bytes :type)
(defmulti generate-keystream :type)

(defmulti pad :pad)
(defmulti unpad :pad)

(defn bytes-to-pad
  "Calculate the remaining number of bytes to add to make a full block.

  (bytes-to-pad 15 16) => 1
  (bytes-to-pad 17 16) => 15"
  [total-bytes bytes-per-block]
  (let [x (mod total-bytes bytes-per-block)]
    (if (zero? x)
      x
      (- bytes-per-block x))))

(defn- ed-dispatcher [{:keys [type mode pad]
                       :or   {type :aes mode :cbc pad :x923}}]
  (str type mode pad))

(defmulti encrypt ed-dispatcher)
(defmulti decrypt ed-dispatcher)

(def ^{:doc      "Calculates the bytes per block for the given block cipher"
       :arglists '([cipherkw])}
  bytes-per-block
  (memoize
    (fn [cipherkw]
      (/ (blocksize-bits {:type cipherkw}) 8))))

(defn l->hex
  "Convert a Long (0-255) to a 2-digit hex string.

  Note that in Clojure numbers are Longs by default and must be converted via
  .intValue to an Integer to convert to a hex string

  (l->hex 5) => \"05\"
  (l->hex 204) => \"cc\""
  [l]
  (let [val (Integer/toHexString (.intValue l))]
    (if (= 1 (count val))
      (str "0" val)
      val)))

(defn hex->l
  "Convert a hex string into a Long"
  [hex]
  (Long/parseLong hex 16))

(defn every-byte?
  "Evaluates to true if every value in a sequence is between 0 to 255 inclusive"
  [s]
  (every? true? (map #(and (>= % 0) (<= % 255)) s)))

(defn bv->hex
  "Convert a vector of bytes (0-255) into a hex string."
  [v]
  (if (every-byte? v)
    (->> v (map l->hex) (apply str))))

(defn hex->bv
  "Convert a string of hex values into a vectory of byte values (0-255)"
  [hex]
  (->> hex
       (partition-all 2)
       (map (partial apply str))
       (map hex->l)
       vec))

(defn bv->str
  "Convert a vector of bytes to a string"
  [bv]
  (apply str (map char bv)))

(defn str->bv
  "Convert a string to a vector of bytes"
  [str]
  (vec (.getBytes str)))

(comment
  (def aim (initialize {:type :aes :pad :x923 :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}))
  (bv->hex (encrypt-block aim (pad aim (str->bv "this is a test!"))))
  (bv->str (unpad aim (decrypt-block aim (hex->bv "05cc8ec2c0ce2977bfa211eb104a0511")))))