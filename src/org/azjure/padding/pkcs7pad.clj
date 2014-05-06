;; ## PKCS7pad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with <em>N</em>
;; bytes of value <em>N</em>

(ns org.azjure.padding.pkcs7pad
  {:author "Jason Ozias"}
  (:require [org.azjure.libcrypt :refer [mbpb]]
            [org.azjure.padding.pad :refer [Pad remaining]]))

;; ### pad-bytes
;; Pad the given vector of bytes to the appropriate block size
;; as defined by the cipher.
;;
;; Evaluates to a vector of bytes padded to the blocksize of
;; the given cipher
(defn- pad-bytes [bytes cipher]
  (let [rem (remaining (count bytes) (mbpb cipher))]
    (reduce conj bytes (take rem (cycle [rem])))))

;; ### unpad-bytes
;; Unpad the given vector of bytes.
;;
;; Evaluates to a vector of bytes.
;;
;; This is the inverse of pad-bytes.
(defn- unpad-bytes [bytes]
  (subvec bytes 0 (- (count bytes) (last bytes))))

;; ### PKCS7pad
;; Extend the Pad protocol through the PKCS7pad record type.
(defrecord PKCS7pad []
  Pad
  (pad [_ bytes cipher]
    (pad-bytes bytes cipher))
  (unpad [_ bytes]
    (unpad-bytes bytes)))
