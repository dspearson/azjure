;; [azjure]: https://crazysacx.github.io/azjure
;; [cipher]: azjure.cipher.cipher.html
;; [modes]: azjure.modes.html
;; [pad]: azjure.padders.html
;; [encoders]: azjure.encoders.html

(ns azjure.core
  "## Core
  API entry point for encryption/decryption.

  See the [azjure] [azjure] homepage for more detailed usage information."
  {:author "Jason Ozias"}
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.cipher.streamcipher :refer :all]
            [azjure.encoders :refer :all]
            [azjure.modes :refer :all]
            [azjure.padders :refer :all])
  (:import (java.security SecureRandom)))

(defn encrypt
  "### encrypt
  Encrypt the given input `x` based on the configuration supplied in the map
  `m`.

  The map has the following format:

    {:type :typekw
     :mode :modekw
     :pad  :padderkw
     :eid  :input-decoderkw
     :eoe  :output-encoderkw
     :did  :input-decoderkw
     :doe  :output-encoderkw
     :key  []
     :iv   []}

  * **type** - A keyword that identifies the cipher you wish to use. See
  [azjure.cipher.cipher] [cipher] for supported values.
  * **mode** - A keyword that identifies the block chaining mode you wish to
  use. See [azjure.modes] [modes] for supported values.
  * **pad** - A keyword that identifies the padder you wish to use. See
  [azjure.padders] [pad] for supported values.
  * **eid** - A keyword that represents the encryption input decoder you wish to
  use. See [azjure.encoders] [encoders] for supported values.
  * **eoe** - A keyword that represents the encryption output encoder you wish
  to use. See [azjure.encoders] [encoders] for supported values.
  * **did** - A keyword that represents the decryption input decoder you wish to
  use. See [azjure.encoders] [encoders] for supported values.
  * **doe** - A keyword that represents the decryption output encoder you wish
  to use. See [azjure.encoders] [encoders] for supported values.
  * **key** - A vector of unsigned bytes (0-255) of the appropriate length that
  represents the key you wish to use with the cipher.
  * **iv** - A vector of unsigned bytes (0-255) of the appropriate length that
  represents the IV you wish to use with the block chaining mode.

#### Example

    {:type :aes :mode :ctr :pad :x923
     :eid  :str :eoe :hex
     :did  :hex :doe :str
     :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
     :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}

  For the example above, this represents the AES cipher, used in Counter mode,
  with ANSI X.923 padding.  The encryption input is expected to be a string, and
  encryption will output a hex string.  For decryption, the input is expected to
  be a hex string, and the output will be encoded as a string.  The key and iv
  are vectors of 128-bits of 0."
  {:added "0.2.0"}
  [x m]
  (let [m (initialize m)]
    (->> (input-decoder m x)
         (pad m)
         (encrypt-blocks m)
         (output-encoder m))))

(defn decrypt
  "### decrypt
  Decrypt the given input `x` based on the configuration supplied in the map
  `m`.  The map has the same format as described in the `encrypt`
  documentation."
  {:added "0.2.0"}
  [x m]
  (let [m (initialize m)]
    (output-encoder
      m
      (->> (input-decoder m x :encryption false)
           (decrypt-blocks m)
           (unpad m))
      :encryption false)))

(defn encrypted-stream
  "### encrypted-stream
  Use a stream cipher to generate an encrypted stream of bytes from the given
  sequence `xs`.  The map `m` has the same format as decribed in the `encrypt`
  documentation."
  {:added "0.2.0"}
  [xs m]
  (let [m (initialize m)
        _ (println m)]
    (->> (input-decoder m xs)
         (generate-keystream m)
         (reduce into)
         (output-encoder m))))

(defn gen-key
  "### gen-key
  Generate a key of length `x` bits.  `x` should be a positive multiple of 8.

  Evaluates to a vector of unsigned (0 - 255) byte values."
  {:added "0.2.0"}
  [x]
  {:pre [(pos? x) (zero? (mod x 8))]}
  (let [barr (byte-array (/ x 8))
        _ (.nextBytes (SecureRandom.) barr)]
    (mapv (partial + 128) (vec barr))))