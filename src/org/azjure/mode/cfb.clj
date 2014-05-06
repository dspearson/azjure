;; ## Cipher Feedback
;; Cipher Feedback mode (CFB-8) where 8 bits (1 byte) are encrypted/decrypted
;; per round.
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)

(ns org.azjure.mode.cfb
  {:author "Jason Ozias"}
  (:require [org.azjure.cipher.blockcipher :as bc]
            [org.azjure.mode.modeofoperation :refer [ModeOfOperation]]))

;; ### encrypt-byte
;; Encrypt a single byte given the cipher,
;; key, and initialization vector.  The
;; first byte is pulled from the keystream
;; in and xor'd with the given byte to form
;; the encrypted byte.
;;
;; Evaluates to a byte value (0-255)
(defn- ^{:doc "Encrypt a single byte"}
  encrypt-byte [cipher key iv byte]
  (->> (bc/encrypt-block cipher iv key)
       (first)
       (bit-xor byte)))

;; ### shift-in
;; For the given cipher shift <em>val</em>
;; into the last position.
;;
;; Evaluates to a vector of bytes
(defn- shift-in [cipher reg val]
  (->> (conj reg val)
       (take-last (quot (bc/blocksize cipher) 8))
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
