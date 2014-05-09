(ns azjure.cipher.streamcipher
  {:author "Jason Ozias"})

(defmulti iv-size-bits
          "Evaluates to the IV size in bits supported by the stream cipher in
  bits"
          :type)
(defmulti keystream-size-bits
          "Evaluates to the keystream size supported by the stream cipher in
  bits"
          :type)
(defmulti generate-keystream
          "Generate the stream cipher keystream"
          :type)