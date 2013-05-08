(ns net.ozias.crypt.mode.modeofoperation)

(defprotocol ModeOfOperation
  (encrypt-blocks [_ blocks iv key])
  (decrypt-blocks [_ blocks iv key]))
