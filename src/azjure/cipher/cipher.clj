;; [core]: azjure.core.html

(ns azjure.cipher.cipher
  "## Cipher
  Cipher multimethod definitions.

  All ciphers should define defmethods for these multimethods.

  The currently supported cipher type keywords for use in the configuration map
  are:

  * `:aes` - AES
  * `:bf` - Blowfish
  * `:cast5` - CAST5
  * `:tf` - Twofish

Note that if no `:type` is supplied in the configuration map, `:aes` will be
assumed."
  {:author "Jason Ozias"})

(defmulti initialize
          "### initialize
  Takes a configuration map as defined in [azjure.core] [core] as the argument.

  Ciphers implementing this method should assoc any information needed during
  encryption/decryption (such as key schedules) into the configuration map
  during initialization.

  This function should evaluate to the configuration map with any additional
  information assoc'd into it."
          {:arglists '([m])
           :added    "0.2.0"}
          :type)

(defmulti keysizes-bits
          "### keysizes-bits
  Ciphers implementing this multimethod should return a vector of values
  representing the key sizes (in bits) supported by the cipher.

  For example, AES supports key sizes of 128, 192, and 256 bits.  This function
  would then evaluate to `[128 192 256]` if called for AES."
          {:arglists '([])
           :added    "0.2.0"}
          :type)