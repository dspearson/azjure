;; ## Twofish
;; Designed to meet the spec at
;; [https://www.schneier.com/paper-twofish-paper.pdf](https://www.schneier.com/paper-twofish-paper.pdf)
(ns net.ozias.crypt.cipher.twofish
  (:require [net.ozias.crypt.cipher.blockcipher :refer [BlockCipher]]))

;; ### Twofish
;; Extend the BlockCipher protocol thorough the Twofish record type
(defrecord Twofish []
  BlockCipher
  (encrypt-block [_ block key]
    block)
  (decrypt-block [_ block key]
    block)
  (blocksize [_]
    128))
