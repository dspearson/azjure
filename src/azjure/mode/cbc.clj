(ns azjure.mode.cbc
  (:require [azjure.core :as core]))

(defn- ^{:added "0.2.0"} encrypt-blocks
  "Encrypt the given plaintext."
  [m bv]
  (reduce
    (fn [ciphertext bytes]
      (let [civ (if (empty? ciphertext)
                  (:iv m)
                  (subvec ciphertext
                          (- (count ciphertext)
                             (core/bytes-per-block (:type m)))))]
        (reduce conj ciphertext (core/encrypt-block m (mapv bit-xor bytes civ)))))
    [] (partition (core/bytes-per-block (:type m)) bv)))

(defn- ^{:added "0.2.0"} decrypt-blocks
  "Decrypt the given ciphertext."
  [m ciphertext]
  (let [bpb (core/bytes-per-block (:type m))]
    (reduce
      (fn [plaintext idx]
        (let [lower (* bpb idx)
              upper (+ bpb lower)
              block (subvec ciphertext lower upper)
              civ (if (zero? idx)
                    (:iv m)
                    (subvec ciphertext (- lower bpb) (- upper bpb)))]
          (reduce conj plaintext
                  (mapv bit-xor (core/decrypt-block m block) civ))))
      [] (range (/ (count ciphertext) (core/bytes-per-block (:type m)))))))

(defmethod core/encrypt-blocks :cbc [m bv] (encrypt-blocks m bv))
(defmethod core/decrypt-blocks :cbc [m bv] (decrypt-blocks m bv))