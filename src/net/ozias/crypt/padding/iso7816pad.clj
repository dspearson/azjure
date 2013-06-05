;; ## iso7816pad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with 0x80
;; followed by zeros
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.iso7816pad
  (:require [net.ozias.crypt.libcrypt :refer (mbpb)]
            [net.ozias.crypt.padding.pad :refer (Pad remaining)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### pad-bytes
;; Pad the given vector of bytes to the appropriate block size
;; as defined by the cipher.
;;
;; Evaluates to a vector of bytes.
(defn- pad-bytes [bytes cipher]
  (let [l (count bytes)
        rem (remaining l (mbpb cipher))
        zeropad (reduce conj bytes (take rem (cycle [0])))]
    (assoc zeropad l 0x80)))

;; ### unpad-bytes
;; Unpad the given vector of bytes.
;;
;; Evaluates to a vector of bytes.
;;
;; This is the inverse of pad-bytes.
(defn- unpad-bytes [bytes]
  (->> (reverse bytes)
       (drop-while zero?)
       (rest)
       (reverse)
       (vec)))

;; ### ISO7816pad
;; Extend the Pad protocol through the ISO7816pad record type.
(defrecord ISO7816pad []
  Pad
  (pad [_ bytes cipher]
    (pad-bytes bytes cipher))
  (unpad [_ bytes]
    (unpad-bytes bytes)))
