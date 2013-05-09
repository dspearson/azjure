(ns ^{:author "Jason Ozias"}
    net.ozias.crypt.mode.cbc
    (:require [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
              [net.ozias.crypt.cipher.blockcipher :as bc]))

(defn- encrypt-block [cipher iv key] 
  (fn [ciphertext block]
    (let [civ (if (empty? ciphertext) 
                iv 
                (subvec ciphertext (- (count ciphertext) 4)))]
      (reduce conj ciphertext 
              (bc/encrypt-block cipher
                                (mapv #(bit-xor %1 %2) block civ) key)))))

(defn- decrypt-block [cipher ciphertext iv key]
  (fn [plaintext idx]
    (let [lower (* 4 idx)
          upper (+ 4 lower)
          block (subvec ciphertext lower upper)
          civ (if (= 0 idx)
                iv 
                (subvec ciphertext (- lower 4) (- upper 4)))]
      (reduce conj plaintext (mapv #(bit-xor %1 %2) 
                                   (bc/decrypt-block cipher block key) civ)))))

(defrecord CipherBlockChaining []
  ModeOfOperation
  (encrypt-blocks [_ cipher iv blocks key]
    (reduce #((encrypt-block cipher iv key) %1 %2) [] (partition 4 blocks)))
  (decrypt-blocks [_ cipher iv blocks key]
    (reduce #((decrypt-block cipher blocks iv key) %1 %2) []  (range (/ (count blocks) 4)))))    
