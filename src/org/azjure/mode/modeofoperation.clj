;; ## Mode Of Operation Protocol

(ns org.azjure.mode.modeofoperation)

;; ### ModeOfOperation
;; The protocol defines two functions
;;
;; #### encrypt
;; This function should encrypt the given bytes using the suppplied
;; cipher, initialization vector, and key.
;;
;; #### decrypt
;; This function should decrypt the given bytes using the supplied
;; cipher, initialization vector, and key.
(defprotocol ModeOfOperation
  (encrypt [_ cipher key iv bytes])
  (decrypt [_ cipher key iv bytes]))
