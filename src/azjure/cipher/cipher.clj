(ns azjure.cipher.cipher)

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