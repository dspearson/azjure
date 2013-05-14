;; ## Zeropad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with zeros
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.zeropad
  (:require [net.ozias.crypt.libbyte :refer (bytes-word)]
            [net.ozias.crypt.padding.pad :refer (Pad remaining)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### pad-bytes
;; Pad the given byte array to the appropriate block size
;; as defined by the cipher.
;;
;; Evaluates to a vector of <em>N</em> 32-bit words, where
;; <em>N</em> is the number of words per block.
(defn- pad-bytes [unpadded cipher]
  (let [words-per-block (/ (bc/blocksize cipher) 32)
        bytes-per-block (/ (bc/blocksize cipher) 8)
        bytes-per-word (/ bytes-per-block words-per-block)
        l (count unpadded)
        rem (remaining l bytes-per-block)
        zeropad (reduce conj unpadded (take rem (cycle [0])))]
    (mapv #(bytes-word %) (partition bytes-per-word zeropad))))

;; ### Zeropad
;; Extend the Pad protocol through the Zeropad record type.
(defrecord Zeropad []
  Pad
  (pad [_ unpadded cipher]
    (pad-bytes (vec unpadded) cipher))
  (unpad [_ padded cipher]
    padded))
