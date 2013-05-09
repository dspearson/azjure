(ns net.ozias.crypt.cipher.twofish
  (:require [net.ozias.crypt.cipher.blockcipher :refer [BlockCipher]]))

(defrecord Twofish []
  BlockCipher
  (encrypt-block [_ block key]
    block)
  (decrypt-block [_ block key]
    block)
  (blocksize [_]
    128))
