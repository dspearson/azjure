;; ## Cipher Feedback
;; Cipher Feedback mode (CFB-8) where 8 bits (1 byte) are encrypted/decrypted
;; per round.
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
(ns ^{:author "Jason Ozias"}
  org.azjure.mode.cfb
  (:require [org.azjure.libcrypt :refer [mwpb]]
            [org.azjure.mode.modeofoperation :refer [ModeOfOperation]]
            [org.azjure.cipher.streamcipher :as sc]))

;; ### encrypt-byte
;; Encrypt a single byte given the cipher,
;; key, and initialization vector.  The
;; first byte is pulled from the keystream
;; in and xor'd with the given byte to form
;; the encrypted byte.
;;
;; Evaluates to a byte value (0-255)
(defn- encrypt-byte [cipher key iv byte]
  (->> (sc/generate-keystream cipher key iv)
       (first)
       (bit-xor byte)))

;; ### shift-in
;; For the given cipher shift <em>val</em>
;; into the last position.
;;
;; Evaluates to a vector of bytes
(defn- shift-in [cipher reg val]
  (->> (conj reg val)
       (take-last (sc/iv-size-bytes cipher))
       (vec)))

;; ### cfb-round
;; Function representing a Cipher Feedback round
;; over a given key and cipher.  <em>enc</em> is true
;; if encrypting, false if decrypting.
;;
;; Evaluates to a vector of 2 vectors. The first vector
;; represents the running state of each encrypt round.
;; The second vector represents the next value to use
;; as an IV.
(defn- cfb-round [cipher key enc] 
  (fn [[out iv] byte]
    (let [ebyte (encrypt-byte cipher key iv byte)
          sval (if enc ebyte byte)]
      [(conj out ebyte) (shift-in cipher iv sval)])))

;; ### process-bytes
;; Process the given bytes vector with the given key and
;; initialization vector. <em>enc</em> is true if you are
;; encrypting, false otherwise.
;;
;; Evaluates to a vector of bytes
(defn- process-bytes [cipher key iv bytes enc]
  (first (reduce (cfb-round cipher key enc) [[] iv] bytes)))

;; ### CipherFeedback
;; Extend the ModeOfOperation protocol through the CipherFeedback record.
(defrecord CipherFeedback []
  ModeOfOperation
  (encrypt [_ cipher key iv bytes]
    (process-bytes cipher key iv bytes true))
  (decrypt [_ cipher key iv bytes]
    (process-bytes cipher key iv bytes false)))
