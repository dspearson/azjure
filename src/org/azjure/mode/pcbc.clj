;; ## Propagating Cipher-Block Chaining
;; Propagating Cipher-Block Chaining mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
;; > "The propagating cipher block chaining mode was designed to cause small
;; > changes in the ciphertext to propagate indefinitely when decrypting, as
;; > well as when encrypting."
;;
(ns ^{:author "Jason Ozias"}
  org.azjure.mode.pcbc
  (:require [org.azjure.libcrypt :refer [mbpb]]
            [org.azjure.mode.modeofoperation :refer [ModeOfOperation]]
            [org.azjure.cipher.blockcipher :as bc]))

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
    (let [encrypted (bc/encrypt-block cipher (mapv bit-xor iv block) key)
          ciphertext (reduce conj ct encrypted)]
      [(mapv bit-xor block encrypted)
       ciphertext])))

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
    (let [decrypted (bc/decrypt-block cipher block key)
          plaintext (mapv bit-xor iv decrypted)]
      [(mapv bit-xor block plaintext)
       (reduce conj pt plaintext)])))

;; ### PropagatingCipherBlockChaining
;; Extend the ModeOfOperation protocol through the 
;; PropagatingCipherBlockChaining record.
(defrecord PropagatingCipherBlockChaining []
  ModeOfOperation
  (encrypt [_ cipher key iv bytes]
    (last (reduce (encrypt-block cipher key) [iv []] (partition (mbpb cipher) bytes))))
  (decrypt [_ cipher key iv bytes]
    (last (reduce (decrypt-block cipher key) [iv []] (partition (mbpb cipher) bytes)))))