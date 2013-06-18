;; ## StreamCipher Protocol
(ns ^{:author "Jason Ozias"}
  org.azjure.cipher.streamcipher)

;; ### StreamCipher
;; This protocol defines three functions
;;
;; #### generate-keystream
;;
;; #### keystream-size-bytes
;;
;; #### iv-size-bytes

(defprotocol StreamCipher
  (generate-keystream [_ initmap iv])
  (keystream-size-bytes [_])
  (iv-size-bytes [_]))
