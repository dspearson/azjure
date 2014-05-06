;; ## Cipher-Block Chaining
;; Cipher-Block Chaining mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
;; > "In CBC mode, each block of plaintext is XORed with the previous ciphertext
;; > block before being encrypted. This way, each ciphertext block depends on all
;; > plaintext blocks processed up to that point. To make each message unique, an
;; > initialization vector must be used in the first block."
;;

(ns org.azjure.mode.cbc
  {:author "Jason Ozias"}
  (:require [org.azjure.cipher.blockcipher :as bc]
            [org.azjure.libcrypt :refer [mbpb]]
            [org.azjure.mode.modeofoperation :refer [ModeOfOperation]]))

;; ### encrypt-block
;; Evaluates to a function over the given cipher, initialization vector and key.
;;
;; The function takes the current ciphertext and the block to encrypt.
;; The block is encrypted and conj'd onto the ciphertext.
(defn- encrypt-block [cipher iv key] 
  (fn [ciphertext bytes]
    (let [civ (if (empty? ciphertext) 
                iv 
                (subvec ciphertext (- (count ciphertext) (mbpb cipher))))]
      (reduce conj ciphertext (bc/encrypt-block cipher (mapv bit-xor bytes civ) key)))))

;; ### decrypt-block
;; Evaluates to a function over the given cipher, ciphertext, 
;; initialization vector and key.
;;
;; The function takes the current plaintext and the index in the ciphertext
;; we are decrypting. The block is decrypted and conj'd onto the plaintext.
(defn- decrypt-block [cipher ciphertext iv key]
  (fn [plaintext idx]
    (let [lower (* (mbpb cipher) idx)
          upper (+ (mbpb cipher) lower)
          block (subvec ciphertext lower upper)
          civ (if (= 0 idx)
                iv 
                (subvec ciphertext (- lower (mbpb cipher)) (- upper (mbpb cipher))))]
      (reduce conj plaintext (mapv bit-xor (bc/decrypt-block cipher block key) civ)))))

;; ### CipherBlockChaining
;; Extend the ModeOfOperation protocol through the CipherBlockChaining record.
(defrecord CipherBlockChaining []
  ModeOfOperation
  (encrypt [_ cipher key iv bytes]
    (reduce (encrypt-block cipher iv key) [] (partition (mbpb cipher) bytes)))
  (decrypt [_ cipher key iv bytes]
    (reduce (decrypt-block cipher bytes iv key) []  (range (/ (count bytes) (mbpb cipher))))))    
