;; ## iso10126pad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with random bytes
;; and a final byte indicating how many pad bytes were added.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.iso10126pad
  (:require [net.ozias.crypt.libcrypt :refer (mbpb)]
            [net.ozias.crypt.padding.pad :refer (Pad remaining)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### pad-bytes
;; Pad the given vector of bytes to the appropriate block size
;; as defined by the cipher.
;;
;; Evaluates to a vector of bytes padded to the blocksize of
;; the given cipher
(defn- pad-bytes [bytes cipher]
  (let [rem (remaining (count bytes) (mbpb cipher))
        randompad (reduce conj bytes (take rem (repeatedly #(rand-int 256))))]
    (assoc randompad (- (count randompad) 1) rem)))

;; ### unpad-bytes
;; Unpad the given vector of bytes.
;;
;; Evaluates to a vector of bytes.
;;
;; This is the inverse of pad-bytes.
(defn- unpad-bytes [bytes]
  (subvec bytes 0 (- (count bytes) (last bytes))))

;; ### ISO10126pad
;; Extend the Pad protocol through the ISO10126pad record type.
(defrecord ISO10126pad []
  Pad
  (pad [_ bytes cipher]
    (pad-bytes bytes cipher))
  (unpad [_ bytes]
    (unpad-bytes bytes)))
