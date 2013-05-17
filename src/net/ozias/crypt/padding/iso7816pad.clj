;; ## iso7816pad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with 0x80
;; followed by zeros
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.iso7816pad
  (:require [net.ozias.crypt.libbyte :refer (bytes-word word-bytes)]
            [net.ozias.crypt.padding.pad :refer (Pad remaining)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### pad-bytes
;; Pad the given byte array to the appropriate block size
;; as defined by the cipher.
;;
;; Evaluates to a vector of <em>N</em> 32-bit words, where
;; <em>N</em> is the number of words per block.
(defn- pad-bytes [unpadded cipher]
  (let [wpb (/ (bc/blocksize cipher) 32)
        bpb (/ (bc/blocksize cipher) 8)
        bpw (/ bpb wpb)
        l (count unpadded)
        rem (remaining l bpb)
        zeropad (reduce conj unpadded (take rem (cycle [0])))]
    (mapv #(bytes-word %) (partition bpw (assoc zeropad l 0x80)))))

;; ### unpad-blocks
;; Unpad the given vector of words.
;;
;; Evaluates to a byte array.
;;
;; This is the inverse of pad-bytes.
(defn- unpad-blocks [padded cipher]
  (let [revflat (reverse (reduce into (mapv #(word-bytes %) padded)))
        trimmed (into [] (drop-while #(= 0 %) revflat))]
    (byte-array (map byte (reverse (subvec trimmed 1))))))

;; ### ISO7816pad
;; Extend the Pad protocol through the ISO7816pad record type.
(defrecord ISO7816pad []
  Pad
  (pad [_ unpadded cipher]
    (pad-bytes (vec unpadded) cipher))
  (unpad [_ padded cipher]
    (unpad-blocks padded cipher)))
