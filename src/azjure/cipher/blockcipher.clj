(ns azjure.cipher.blockcipher
  {:author "Jason Ozias"})

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