;; ## Blowfish Cipher
;; Designed 
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.blowfish
  (:require [net.ozias.crypt.cipher.blockcipher :refer [BlockCipher]]))

(defrecord Blowfish []
  BlockCipher
  (encrypt-block [_ block key]
    block)
  (decrypt-block [_ block key]
    block)
  (blocksize [_]
    64))
