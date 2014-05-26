(ns azjure.cipher.blockcipher
  "## Block Cipher
  Block cipher multimethod definitions.

  All block ciphers should define defmethods for these multimethods.

  The currently supported block cipher type keywords for use in the
  configuration map are:

    :aes     - AES
    :bf      - Blowfish
    :cast6   - CAST6
    :tea     - TEA
    :tf      - Twofish
    :xtea    - XTEA"
  {:author "Jason Ozias"})

(defmulti blocksize-bits
          "### blocksize-bits
  Evaluates to the block size in bits supported by the block cipher."
          {:arglists '([])
           :added    "0.2.0"}
          :type)

(defmulti encrypt-block
          "### encrypt-block
  Takes an initmap and a vector of byte values of the appropriate block size for
  the cipher and encrypts it."
          {:arglists '([m block])
           :added    "0.2.0"}
          :type)

(defmulti decrypt-block
          "### decrypt-block
  Takes an initmap and a vector of byte values of the appropriate block size for
  the cipher and decrypts it."
          {:arglists '([m block])
           :added    "0.2.0"}
          :type)

(def ^{:arglists '([m])
       :added    "0.2.0"}
  bytes-per-block
  "### bytes-per-block
  Calculates the bytes per block for the given block cipher configuration."
  (memoize (fn [m] (/ (blocksize-bits m) 8))))