;; ## Output Feedback
;; Output Feedback mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.ofb
  (:require [net.ozias.crypt.libcrypt :refer [mwpb]]
            [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### encrypt-block
;; Evaluates to a function over the given cipher and key.
;;
;; * <em>[iv ct]</em> - The initialization vector for the current block and
;; the ciphertext vector.
;; * <em>block</em> - The block we are decrypting.
;;
;; Evaluates to a vector containing the IV to use with the next block and
;; the current state of the ciphertext vector.
(defn- encrypt-block [cipher key]
  (fn [[iv ct] block]
    (let [encrypted (bc/encrypt-block cipher iv key)
          ciphertext (mapv #(bit-xor %1 %2) block encrypted)]
      [encrypted
       (reduce conj ct ciphertext)])))

;; ### decrypt-block
;; Evaluates to a function over the given cipher and key.
;;
;; * <em>[iv pt]</em> - The initialization vector for the current block and
;; the plaintext vector.
;; * <em>block</em> - The block we are decrypting.
;;
;; Evaluates to a vector containing the IV to use with the next block and
;; the current state of the plaintext vector.
(defn- decrypt-block [cipher key]
  (fn [[iv pt] block]
    (let [decrypted (bc/encrypt-block cipher iv key)
          plaintext (mapv #(bit-xor %1 %2) decrypted block)]
      [decrypted
       (reduce conj pt plaintext)])))
      
;; ### OutputFeedback
;; Extend the ModeOfOperation protocol through the OutputFeedback record.
(defrecord OutputFeedback []
  ModeOfOperation
  (encrypt-blocks [_ cipher iv blocks key]
    (last (reduce #((encrypt-block cipher key) %1 %2) [iv []] (partition (mwpb cipher) blocks))))
  (decrypt-blocks [_ cipher iv blocks key]
    (last (reduce #((decrypt-block cipher key) %1 %2) [iv []] (partition (mwpb cipher) blocks)))))
