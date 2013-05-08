(ns net.ozias.crypt.padding.pad)

(defprotocol Pad
  (pad-last-block [_ unpadded blocksize]))
