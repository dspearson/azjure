;; ## PKCS7pad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with <em>N</em>
;; bytes of value <em>N</em>
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.pkcs7pad
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
        rem (remaining (count unpadded) bytes-per-block)
        rempad (reduce conj unpadded (take rem (cycle [rem])))]
    (mapv #(bytes-word %) (partition bytes-per-word rempad))))

;; ### PKCS7pad
;; Extend the Pad protocol through the PKCS7pad record type.
(defrecord PKCS7pad []
  Pad
  (pad [_ unpadded cipher]
    (pad-bytes (vec unpadded) cipher))
  (unpad [_ padded cipher]
    padded))
