(ns azjure.modes
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.padders :refer [bytes-per-block]]))

(defmulti encrypt-blocks
          "Encrypt a vector of bytes padded to a multiple of the block size of
    the cipher.  All block modes should implement this method."
          {:arglists '([m bv])
           :added    "0.2.0"}
          :mode)

(defmulti decrypt-blocks
          "Decrypt a vector of bytes padded to a multiple of the block size of
    the cipher.  All block modes should implement this method."
          {:arglists '([m bv])
           :added    "0.2.0"}
          :mode)

(defmethod encrypt-blocks :cbc [m bv]
  (reduce
    (fn [ciphertext bytes]
      (let [civ (if (empty? ciphertext)
                  (:iv m)
                  (subvec ciphertext
                          (- (count ciphertext)
                             (bytes-per-block (:type m)))))]
        (reduce conj ciphertext (encrypt-block m (mapv bit-xor bytes civ)))))
    [] (partition (bytes-per-block (:type m)) bv)))

(defmethod decrypt-blocks :cbc [m bv]
  (let [bpb (bytes-per-block (:type m))]
    (reduce
      (fn [plaintext idx]
        (let [lower (* bpb idx)
              upper (+ bpb lower)
              block (subvec bv lower upper)
              civ (if (zero? idx)
                    (:iv m)
                    (subvec bv (- lower bpb) (- upper bpb)))]
          (reduce conj plaintext
                  (mapv bit-xor (decrypt-block m block) civ))))
      [] (range (/ (count bv) bpb)))))

(defmethod encrypt-blocks :ecb [m bv]
  (reduce into (mapv (partial encrypt-block m)
                     (partition (bytes-per-block (:type m)) bv))))

(defmethod decrypt-blocks :ecb [m bv]
  (reduce into (mapv (partial decrypt-block m)
                     (partition (bytes-per-block (:type m)) bv))))