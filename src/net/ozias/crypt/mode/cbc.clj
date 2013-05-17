;; ## Cipher-Block Chaining
;; Cipher-Block Chaining mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
;; > "In CBC mode, each block of plaintext is XORed with the previous ciphertext
;; > block before being encrypted. This way, each ciphertext block depends on all
;; > plaintext blocks processed up to that point. To make each message unique, an
;; > initialization vector must be used in the first block."
;;
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.cbc
  (:require [net.ozias.crypt.libcrypt :refer [mwpb]]
            [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### encrypt-block
;; Evaluates to a function over the given cipher, initialization vector and key.
;;
;; The function takes the current ciphertext and the block to encrypt.
;; The block is encrypted and conj'd onto the ciphertext.
(defn- encrypt-block [cipher iv key] 
  (fn [ciphertext block]
    (let [civ (if (empty? ciphertext) 
                iv 
                (subvec ciphertext (- (count ciphertext) (mwpb cipher))))]
      (reduce conj ciphertext 
              (bc/encrypt-block cipher
                                (mapv #(bit-xor %1 %2) block civ) key)))))

;; ### decrypt-block
;; Evaluates to a function over the given cipher, ciphertext, 
;; initialization vector and key.
;;
;; The function takes the current plaintext and the index in the ciphertext
;; we are decrypting. The block is decrypted and conj'd onto the plaintext.
(defn- decrypt-block [cipher ciphertext iv key]
  (fn [plaintext idx]
    (let [lower (* (mwpb cipher) idx)
          upper (+ (mwpb cipher) lower)
          block (subvec ciphertext lower upper)
          civ (if (= 0 idx)
                iv 
                (subvec ciphertext (- lower (mwpb cipher)) (- upper (mwpb cipher))))]
      (reduce conj plaintext (mapv #(bit-xor %1 %2) 
                                   (bc/decrypt-block cipher block key) civ)))))

;; ### CipherBlockChaining
;; Extend the ModeOfOperation protocol through the CipherBlockChaining record.
(defrecord CipherBlockChaining []
  ModeOfOperation
  (encrypt-blocks [_ cipher iv blocks key]
    (reduce #((encrypt-block cipher iv key) %1 %2) [] (partition (mwpb cipher) blocks)))
  (decrypt-blocks [_ cipher iv blocks key]
    (reduce #((decrypt-block cipher blocks iv key) %1 %2) []  (range (/ (count blocks) (mwpb cipher))))))    
