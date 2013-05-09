;; ## BlockCipher Protocol
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.blockcipher)

;; ### BlockCipher
;; This protocol defines three functions
;;
;; #### encrypt-block
;; This function takes the block to be encrypted and
;; the key that should be used to encrypt the block.
;;
;; #### decrypt-block
;; This function takes the block to be decrypted and
;; the key that should be used to decrypt the block.
;; 
;; #### blocksize
;; This function should evaluate to the blocksize in bits
;;
(defprotocol BlockCipher
  (encrypt-block [_ block key])
  (decrypt-block [_ block key])
  (blocksize [_]))
