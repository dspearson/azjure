;; ## StreamCipher Protocol
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.streamcipher)

;; ### StreamCipher
;; This protocol defines two functions
;;
;; #### process-byte
;; This function takes a byte and encrypts/decrypts
;; it returning a byte result
;;
;; #### process-bytes
;; This function takes a vectors of bytes and
;; processes them returning a vector of bytes
;; 
(defprotocol StreamCipher
  (process-byte [_ byte])
  (process-bytes [_ bytes]))
