(ns ^{:author "Jason Ozias"}
    net.ozias.crypt.mode.cbc
    (:require [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
              [net.ozias.crypt.cipher.blockcipher :as bc]))

(defn- block-in-words [cipher]
  (/ (bc/blocksize cipher) 32))

(def mbiw (memoize block-in-words))

(defn- encrypt-block [cipher iv key] 
  (fn [ciphertext block]
    (let [civ (if (empty? ciphertext) 
                iv 
                (subvec ciphertext (- (count ciphertext) (mbiw cipher))))]
      (reduce conj ciphertext 
              (bc/encrypt-block cipher
                                (mapv #(bit-xor %1 %2) block civ) key)))))

(defn- decrypt-block [cipher ciphertext iv key]
  (fn [plaintext idx]
    (let [lower (* (mbiw cipher) idx)
          upper (+ (mbiw cipher) lower)
          block (subvec ciphertext lower upper)
          civ (if (= 0 idx)
                iv 
                (subvec ciphertext (- lower (mbiw cipher)) (- upper (mbiw cipher))))]
      (reduce conj plaintext (mapv #(bit-xor %1 %2) 
                                   (bc/decrypt-block cipher block key) civ)))))

(defrecord CipherBlockChaining []
  ModeOfOperation
  (encrypt-blocks [_ cipher iv blocks key]
    (reduce #((encrypt-block cipher iv key) %1 %2) [] (partition (mbiw cipher) blocks)))
  (decrypt-blocks [_ cipher iv blocks key]
    (reduce #((decrypt-block cipher blocks iv key) %1 %2) []  (range (/ (count blocks) (mbiw cipher))))))    
