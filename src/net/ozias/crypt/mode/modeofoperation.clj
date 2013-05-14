;; ## Mode Of Operation Protocol
(ns net.ozias.crypt.mode.modeofoperation)

;; ### ModeOfOperation
;; The protocol defines two functions
;;
;; #### encrypt-blocks
;; This function should encrypt the given blocks using the suppplied
;; cipher, initialization vector, and key.
;;
;; #### decrypt-blocks
;; This function should decrypt the given blocks using the supplied
;; cipher, initialization vector, and key.
(defprotocol ModeOfOperation
  (encrypt-blocks [_ cipher iv blocks key])
  (decrypt-blocks [_ cipher iv blocks key]))
