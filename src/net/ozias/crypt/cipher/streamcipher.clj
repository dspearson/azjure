;; ## StreamCipher Protocol
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.cipher.streamcipher)

;; ### StreamCipher
;; This protocol defines two functions
(defprotocol StreamCipher
  (generate-keystream [_ key iv])
  (keystream-size-bytes [_])
  (iv-size-bytes [_]))
