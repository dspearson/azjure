;; ## BlockCipher Protocol

(ns org.azjure.cipher.blockcipher
  {:author "Jason Ozias"})

;; ### BlockCipher
;; This protocol defines three functions
;;
;; #### encrypt-block
;; This function takes the block to be encrypted and
;; the initmap that should be used to encrypt the block.
;;
;; #### decrypt-block
;; This function takes the block to be decrypted and
;; the initmap that should be used to decrypt the block.
;; 
;; #### blocksize
;; This function should evaluate to the blocksize in bits
;;
(defprotocol BlockCipher
  (encrypt-block [_ block initmap])
  (decrypt-block [_ block initmap])
  (blocksize [_]))
