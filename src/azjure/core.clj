;; [azjure]: https://github.com/CraZySacX/azjure
;; [cipher]: azjure.cipher.cipher.html
;; [modes]: azjure.modes.html
;; [pad]: azjure.padders.html
;; [encoders]: azjure.encoders.html
(ns azjure.core
  "Core Azjure API for encryption/decryption.

  See the [azjure] [azjure] homepage for more detailed usage information."
  {:author "Jason Ozias"}
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.encoders :refer :all]
            [azjure.modes :refer :all]
            [azjure.padders :refer :all])
  (:import (java.security SecureRandom)))

(defn encrypt
  "Encrypt the given input `x` based on the configuration supplied in the map
  `m`.

  The map has the following format:

      {:type type
       :mode mode
       :pad  padder
       :eid  input-decoder
       :eoe  output-encoder
       :did  input-decoder
       :doe  output-encoder
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
  * **eoe** - A keyword that represents the encryption output encoder you wish to
  use. See [azjure.encoders] [encoders] for supported values.
  * **did** - A keyword that represents the decryption input decoder you wish to
  use. See [azjure.encoders] [encoders] for supported values.
  * **doe** - A keyword that represents the decryption output encoder you wish to
  use. See [azjure.encoders] [encoders] for supported values.
  * **key** - A vector of unsigned bytes (0-255) of the appropriate length that
  represents the key you wish to use with the cipher.
  * **iv** - A vector of unsigned bytes (0-255) of the appropriate length that
  represents the IV you wish to use with the block chaining mode."
  {:added "0.2.0"}
  [x m]
  (let [m (initialize m)]
    (->> (input-decoder m x)
         (pad m)
         (encrypt-blocks m)
         (output-encoder m))))

(defn decrypt
  "Decrypt the given input `x` based on the configuration supplied in the map
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

(defn gen-key
  "Generate a key of length `x` bits.  `x` should be a positive multiple of 8.

  Evaluates to a vector of unsigned (0 - 255) byte values."
  {:added "0.2.0"}
  [x]
  {:pre [(pos? x) (zero? (mod x 8))]}
  (let [barr (byte-array (/ x 8))
        _ (.nextBytes (SecureRandom.) barr)]
    (mapv (partial + 128) (vec barr))))