(ns ^{:author "Jason Ozias"}
    net.ozias.crypt.mode.cbc
    (:require 
     [net.ozias.crypt.blockcipher.aes
      :refer [process-block]]))

(defn- encrypt-block [iv key] 
  (fn [ciphertext block]
    (let [civ (if (empty? ciphertext) 
                iv 
                (subvec ciphertext (- (count ciphertext) 4)))]
      (reduce conj 
              ciphertext 
              (process-block 
               (mapv #(bit-xor %1 %2) block civ) key true)))))

(defn- decrypt-block [ciphertext iv key]
  (fn [plaintext idx]
    (let [lower (* 4 idx)
          upper (+ 4 lower)
          block (subvec ciphertext lower upper)
          civ (if (= 0 idx)
                iv 
                (subvec ciphertext (- lower 4) (- upper 4)))]
      (reduce conj 
              plaintext 
              (mapv #(bit-xor %1 %2) 
                    (process-block block key false)
                    civ)))))

(defn process-blocks [blocks key iv enc]
  (if enc
    (reduce #((encrypt-block iv key) %1 %2) 
            [] (partition 4 blocks))
    (reduce #((decrypt-block blocks iv key) %1 %2)
            [] 
            (range (/ (count blocks) 4)))))
