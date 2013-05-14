(ns net.ozias.crypt.padding.pad)

(defprotocol Pad
  (pad-blocks [_ unpadded cipher]))
