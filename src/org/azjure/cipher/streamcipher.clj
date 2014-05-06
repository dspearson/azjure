;; ## StreamCipher Protocol

(ns org.azjure.cipher.streamcipher
  {:author "Jason Ozias"})

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
