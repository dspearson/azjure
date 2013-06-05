;; ## Electronic Code Book Mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
;;
;; > The message is divided into blocks and each block is encrypted separately.
;;
;; <em>Note</em>:  This block cipher mode is not recommended for encryption as
;; the result can expose patterns.  It is however useful for testing purposes.
(ns net.ozias.crypt.mode.ecb
  (:require [net.ozias.crypt.libcrypt :refer [mbpb]]
            [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### ElectronicCodebook
;; Extend the ModeOfOperation protocol through the ElectronicCodebook record
(defrecord ElectronicCodebook []
  ModeOfOperation
  (encrypt [_ cipher key _ bytes]
    (reduce into (mapv #(bc/encrypt-block cipher % key) (partition (mbpb cipher) bytes))))
  (decrypt [_ cipher key _ bytes]
    (reduce into (mapv #(bc/decrypt-block cipher % key) (partition (mbpb cipher) bytes)))))
