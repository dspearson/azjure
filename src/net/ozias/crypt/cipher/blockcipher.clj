;; # BlockCipher Protocol
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.blockcipher)

;; ## BlockCipher
;; This protocol defines three functions
;;
;; 1. encrypt-block: This function takes the block to be encrypted and
;; the key that should be used to encrypt the block.
;; 2. decrypt-block: This function takes the block to be encrypted and
;; the key that should be used to encrypt the block.
;; 3. blocksize: This function should evaluate to the blocksize (in bits)
;; supported by the implementation.
;;
(defprotocol BlockCipher
  (encrypt-block [_ block key])
  (decrypt-block [_ block key])
  (blocksize [_]))
