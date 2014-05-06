;; ## Cipher Protocol

(ns org.azjure.cipher.cipher
  {:author "Jason Ozias"})

;; ### Cipher
;; This protocol defines three functions
;;
;; #### initialize
;; This function takes the key and performs any
;; cipher initialization.

;; #### keysizes-bytes
;; This function should evaluate to a vector of valid
;; keysizes (at byte resolution).
;;
(defprotocol Cipher
  (initialize [_ key])
  (keysizes-bytes [_]))
