;; ## iso10126pad
;; Padding implementation that will pad a byte array to
;; the proper length given a block cipher with random bytes
;; and a final byte indicating how many pad bytes were added.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.padding.iso10126pad
  (:require [net.ozias.crypt.libbyte :refer :all]
            [net.ozias.crypt.padding.pad :refer (Pad remaining)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### pad-bytes
;; Pad the given byte array to the appropriate block size
;; as defined by the cipher.  The last byte will be the
;; number of pad bytes.
;;
;; Evaluates to a vector of <em>N</em> 32-bit words, where
;; <em>N</em> is the number of words per block.
(defn- pad-bytes [unpadded cipher]
  (let [wpb (/ (bc/blocksize cipher) 32)
        bpb (/ (bc/blocksize cipher) 8)
        bpw (/ bpb wpb)
        rem (remaining (count unpadded) bpb)
        randompad (reduce conj unpadded (take rem (repeatedly #(rand-int 256))))
        lz (- (count randompad) 1)]
    (mapv #(bytes-word %) (partition bpw (assoc randompad lz rem)))))

;; ### unpad-blocks
;; Unpad the given vector of words.
;;
;; Evaluates to a byte array.
;;
;; This is the inverse of pad-bytes.
(defn- unpad-blocks [padded cipher]
  (let [pl (last-byte (last padded))
        flat (reduce into (mapv #(word-bytes %) padded))]
    (byte-array (map byte (subvec flat 0 (- (count flat) pl))))))

;; ### ISO10126pad
;; Extend the Pad protocol through the ISO10126pad record type.
(defrecord ISO10126pad []
  Pad
  (pad [_ unpadded cipher]
    (pad-bytes (vec unpadded) cipher))
  (unpad [_ padded cipher]
    (unpad-blocks padded cipher)))
