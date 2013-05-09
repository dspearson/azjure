(ns net.ozias.crypt.mode.ecb
  (:require [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

(defrecord ElectronicCodebook []
  ModeOfOperation
  (encrypt-blocks [_ cipher _ blocks key]
    (reduce into (mapv #(bc/encrypt-block cipher % key) (partition 4 blocks))))
  (decrypt-blocks [_ cipher _ blocks key]
    (reduce into (mapv #(bc/decrypt-block cipher % key) (partition 4 blocks)))))
