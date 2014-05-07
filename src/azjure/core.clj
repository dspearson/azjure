(ns azjure.core)

(defmulti initialize
          "Takes an initmap and assocs any additional keys needed by the
  cipher.  All ciphers should implement this method."
          {:arglists '([m])
           :added    "0.2.0"}
          :type)

(defmulti keysizes-bits
          "Evaluates to a vector of key sizes in bits supported by the cipher.
   All ciphers should implement this method."
          {:arglists '([])
           :added    "0.2.0"}
          :type)

(defmulti blocksize-bits
          "Evaluates to the block size in bits supported by the block cipher.
    All block ciphers should implement this method."
          {:arglists '([])
           :added    "0.2.0"}
          :type)

(defmulti encrypt-block
          "Takes an initmap and a vector of byte values of the appropriate block
  size for the cipher and encrypts it.  All block ciphers should implement this
  method.

  Evaluates to a vector of byte values."
          {:arglists '([m block])
           :added    "0.2.0"}
          :type)

(defmulti decrypt-block
          "Takes an initmap and a vector of byte values of the appropriate block
  size for the cipher and decrypts it.  All block ciphers should implement this
  method.

  Evaluates to a vector of byte values."
          {:arglists '([m block])
           :added    "0.2.0"}
          :type)

(comment
  (defmulti iv-size-bytes :type)
  (defmulti keystream-size-bytes :type)
  (defmulti generate-keystream :type))

(defmulti pad
          "Takes an initmap and a vector of bytes and pads it appropriately to
  a multiple of the block size of the cipher.  All padding methods should
  implement this method."
          {:arglists '([m bv])
           :added    "0.2.0"}
          :pad)

(defmulti unpad
          "Takes a vector of bytes and unpads it.  All padding methods should
   implement this method."
          {:arglists '([_ bv])
           :added    "0.2.0"}
          :pad)

(defmulti encrypt-blocks
          "Encrypt a vector of bytes padded to a multiple of the block size of
    the cipher.  All block modes should implement this method."
          {:arglists '([m bv])
           :added    "0.2.0"}
          :mode)

(defmulti decrypt-blocks
          "Decrypt a vector of bytes padded to a multiple of the block size of
    the cipher.  All block modes should implement this method."
          {:arglists '([m bv])
           :added    "0.2.0"}
          :mode)

(comment
  (defn- ed-dispatcher [{:keys [type mode pad]
                         :or   {type :aes mode :cbc pad :x923}}]
    (str type mode pad))

  (defmulti encrypt ed-dispatcher)
  (defmulti decrypt ed-dispatcher))

(defn ^{:added "0.2.0"} bytes-to-pad
  "Calculate the remaining number of bytes to add to make a full block.

  (bytes-to-pad 15 16) => 1
  (bytes-to-pad 17 16) => 15"
  [total-bytes bytes-per-block]
  (let [x (mod total-bytes bytes-per-block)]
    (if (zero? x)
      x
      (- bytes-per-block x))))

(def ^{:doc      "Calculates the bytes per block for the given block cipher"
       :arglists '([cipherkw])
       :added    "0.2.0"}
  bytes-per-block
  (memoize
    (fn [cipherkw]
      (/ (blocksize-bits {:type cipherkw}) 8))))

(defn ^{:added "0.2.0"} l->hex
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
  (apply str (map char bv)))

(defn ^{:added "0.2.0"} str->bv
  "Convert a string to a vector of bytes"
  [str]
  (vec (.getBytes str)))

(comment
(do
  (def pt1 "this is a test")
  (def pt2 "this is a test!")
  (def pt3 "this is a test of multiple blocks!")
  (def e1 "459c5436ece9b15cdd93466e127abdde")
  (def e2 "05cc8ec2c0ce2977bfa211eb104a0511")
  (def e3 (str "e6a08fbbe8a322acbcdb92afbe66ad2ada969a3778ed5a2af07870cc7e261d4"
               "2fb8c6055e754ade717d25534c610b8a0"))
  (def aim (initialize {:type :aes
                        :mode :cbc
                        :pad  :x923
                        :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                        :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})))
  (bv->hex (encrypt-block aim (pad aim (str->bv pt1))))
  (bv->str (unpad aim (decrypt-block aim (hex->bv e1))))
  (bv->hex (encrypt-blocks aim (pad aim (str->bv pt1))))
  (bv->str (unpad aim (decrypt-blocks aim (hex->bv e2))))
  (bv->hex (encrypt-blocks aim (pad aim (str->bv pt3))))
  (bv->str (unpad aim (decrypt-blocks aim (hex->bv e3)))))