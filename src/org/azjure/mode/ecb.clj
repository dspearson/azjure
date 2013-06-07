;; ## Electronic Code Book Mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
;;
;; > The message is divided into blocks and each block is encrypted separately.
;;
;; <em>Note</em>:  This block cipher mode is not recommended for encryption as
;; the result can expose patterns.  It is however useful for testing purposes.
(ns org.azjure.mode.ecb
  (:require [org.azjure.libcrypt :refer [mbpb]]
            [org.azjure.mode.modeofoperation :refer [ModeOfOperation]]
            [org.azjure.cipher.blockcipher :as bc]))

;; ### ElectronicCodebook
;; Extend the ModeOfOperation protocol through the ElectronicCodebook record
(defrecord ElectronicCodebook []
  ModeOfOperation
  (encrypt [_ cipher key _ bytes]
    (reduce into (mapv #(bc/encrypt-block cipher % key) (partition (mbpb cipher) bytes))))
  (decrypt [_ cipher key _ bytes]
    (reduce into (mapv #(bc/decrypt-block cipher % key) (partition (mbpb cipher) bytes)))))
