;; ## Zeropad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with zeros

(ns org.azjure.padding.zeropad
  {:author "Jason Ozias"}
  (:require [org.azjure.libcrypt :refer [mbpb]]
            [org.azjure.padding.pad :refer [Pad remaining]]))

;; ### pad-bytes
;; Pad the given vector of bytes to the appropriate block size
;; as defined by the cipher.
;;
;; Evaluates to a vector of bytes.
(defn- pad-bytes [bytes cipher]
  (->> (cycle [0])
       (take (remaining (count bytes) (mbpb cipher)))
       (reduce conj bytes)))

;; ### unpad-bytes
;; Unpad the given vector of bytes.
;;
;; Evaluates to a vector of bytes.
;;
;; This is the inverse of pad-bytes.
(defn- unpad-bytes [bytes]
  (->> (reverse bytes)
       (drop-while zero?)
       (reverse)
       (vec)))

;; ### Zeropad
;; Extend the Pad protocol through the Zeropad record type.
(defrecord Zeropad []
  Pad
  (pad [_ bytes cipher]
    (pad-bytes bytes cipher))
  (unpad [_ bytes]
    (unpad-bytes bytes)))
