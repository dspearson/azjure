(ns azjure.modes
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.padders :refer [bytes-per-block]]
            [org.azjure.libbyte :refer [word-bytes]])
  (:import (clojure.lang BigInt)))

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
  (->> (partition (bytes-per-block (:type m)) bv)
       (reductions (fn [i pt] (encrypt-block m (map bit-xor i pt))) (:iv m))
       (rest)
       (reduce into)))

(defmethod decrypt-blocks :cbc [m bv]
  (let [ctblocks (partition (bytes-per-block (:type m)) bv)]
    (->> ctblocks
         (map (partial decrypt-block m))
         (reduce into)
         (mapv bit-xor (reduce into (conj ctblocks (:iv m)))))))

(defmethod encrypt-blocks :cfb [m bv]
  (->> (partition (bytes-per-block (:type m)) bv)
       (reductions (fn [i pt] (mapv bit-xor pt (encrypt-block m i))) (:iv m))
       (rest)
       (vec)
       (reduce into)))

(defmethod decrypt-blocks :cfb [m bv]
  (->> (:iv m)
       (conj (partition (bytes-per-block (:type m)) bv))
       (map (partial encrypt-block m))
       (reduce into)
       (mapv bit-xor bv)))

(defn- process-blocks-ecb [m bv encrypting]
  (->> (partition (bytes-per-block (:type m) bv))
       (mapv (partial (if encrypting encrypt-block decrypt-block) m))
       (reduce into)))

(defmethod encrypt-blocks :ecb [m bv] (process-blocks-ecb m bv true))
(defmethod decrypt-blocks :ecb [m bv] (process-blocks-ecb m bv false))

(defn- process-blocks-ofb [m bv]
  (->> (conj (partition (bytes-per-block (:type m)) bv) (:iv m))
       (reductions (fn [iv _] (encrypt-block m iv)) (:iv m))
       (rest)
       (reduce into)
       (mapv bit-xor bv)))

(defmethod encrypt-blocks :ofb [m bv] (process-blocks-ofb m bv))
(defmethod decrypt-blocks :ofb [m bv] (process-blocks-ofb m bv))

(defn- encrypt-block-pcbc [m]
  (fn [[iv ct] block]
    (let [encrypted (encrypt-block m (mapv bit-xor iv block))
          ciphertext (reduce conj ct encrypted)]
      [(mapv bit-xor block encrypted) ciphertext])))

(defn- decrypt-block-pcbc [m]
  (fn [[iv pt] block]
    (let [decrypted (decrypt-block m block)
          plaintext (mapv bit-xor iv decrypted)]
      [(mapv bit-xor block plaintext) (reduce conj pt plaintext)])))

(defn- process-blocks-pcbc [m bv encrypting]
  (let [efn (if encrypting (encrypt-block-pcbc m) (decrypt-block-pcbc m))]
    (->> (partition (bytes-per-block (:type m)) bv)
         (reduce efn [(:iv m) []])
         (last))))

(defmethod encrypt-blocks :pcbc [m bv] (process-blocks-pcbc m bv true))
(defmethod decrypt-blocks :pcbc [m bv] (process-blocks-pcbc m bv false))

(defn bytes->val [bv]
  (let [l (count bv)]
    (reduce #(.or %1 %2) (map #(.shiftLeft (.toBigInteger (bigint (nth bv %1))) %2)
                              (range l)
                              (range (* 8 (dec l)) -1 -8)))))

(defmulti last-byte class)

(defmethod last-byte BigInt [^BigInt v]
  (.longValue (.and v (bigint 0xff))))

(defmethod last-byte BigInteger [^BigInteger v]
  (.longValue (.and v (.toBigInteger (bigint 0xff)))))

(defmethod last-byte Long [v]
  (bit-and 0xff v))

(defmulti val->bytes class)

(defmethod val->bytes BigInteger [^BigInteger v]
  (loop [curr v
         acc []]
    (cond (and (= 0 curr) (empty? acc)) [0]
          (= 0 curr) (vec (reverse acc))
          :else (recur (.shiftRight curr 8) (conj acc (last-byte curr))))))

(defmethod val->bytes BigInt [^BigInt v]
  (loop [curr (.toBigInteger v)
         acc []]
    (cond (and (= 0 curr) (empty? acc)) [0]
          (= 0 curr) (vec (reverse acc))
          :else (recur (.shiftRight curr 8) (conj acc (last-byte curr))))))

(defmethod val->bytes Long [v]
  (loop [curr v
         acc []]
    (cond (and (= 0 curr) (empty? acc)) [0]
          (= 0 curr) (vec (reverse acc))
          :else (recur (unsigned-bit-shift-right curr 8) (conj acc (last-byte curr))))))

(defmulti xor (fn [x _] (class x)))
(defmethod xor Long [x y]
  (bit-xor x y))
(defmethod xor BigInteger [^BigInteger x y]
  (.xor x (.toBigInteger (bigint y))))

(defn- nonce-seq [iv]
  (map (partial xor (bytes->val iv)) (range)))

(defn- expand [bv n]
  (into (vec (take n (repeat 0))) bv))

(defn- nonces [n iv]
  (map #(expand % (- (count iv) (count %)))
       (map val->bytes (take n (nonce-seq iv)))))

(defn- process-blocks-ctr [m bv]
  (let [blocks (partition (bytes-per-block (:type m)) bv)]
    (->> blocks
         (map (fn [nonce b] (mapv bit-xor b (encrypt-block m nonce)))
              (nonces (count blocks) (:iv m)))
         (reduce into))))

(defmethod encrypt-blocks :ctr [m bv] (process-blocks-ctr m bv))
(defmethod decrypt-blocks :ctr [m bv] (process-blocks-ctr m bv))