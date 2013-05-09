(ns net.ozias.crypt.mode.modeofoperation)

(defprotocol ModeOfOperation
  (encrypt-blocks [_ cipher iv blocks key])
  (decrypt-blocks [_ cipher iv blocks key]))
