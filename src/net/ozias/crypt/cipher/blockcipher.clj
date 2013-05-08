(ns net.ozias.crypt.cipher.blockcipher)

(defprotocol BlockCipher
  (encrypt-block [_ block key])
  (decrypt-block [_ block key]))
