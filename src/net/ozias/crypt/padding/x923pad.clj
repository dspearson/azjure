;; ## x923pad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with zeros and
;; a final byte indicating how many pad bytes were added.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.x923pad
  (:require [net.ozias.crypt.libcrypt :refer (mbpb)]
            [net.ozias.crypt.padding.pad :refer (Pad remaining)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### pad-bytes
;; Pad the given vector of bytes to the appropriate block size
;; as defined by the cipher.
;;
;; Evaluates to a vector of bytes.
(defn- pad-bytes [bytes cipher]
  (let [rem (remaining (count bytes) (mbpb cipher))
        zeropad (reduce conj bytes (take rem (cycle [0])))]
    (assoc zeropad (dec (count zeropad)) rem)))

;; ### unpad-bytes
;; Unpad the given vector of bytes.
;;
;; Evaluates to a vector of bytes.
;;
;; This is the inverse of pad-bytes.
(defn- unpad-bytes [bytes]
  (subvec bytes 0 (- (count bytes) (last bytes))))

;; ### X923pad
;; Extend the Pad protocol through the x923pad record type.
(defrecord X923pad []
  Pad
  (pad [_ bytes cipher]
    (pad-bytes bytes cipher))
  (unpad [_ bytes]
    (unpad-bytes bytes)))
