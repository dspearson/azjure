(ns azjure.cipher.streamcipher)

(defmulti iv-size-bytes :type)
(defmulti keystream-size-bytes :type)
(defmulti generate-keystream :type)