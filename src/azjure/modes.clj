(ns azjure.modes
  {:author "Jason Ozias"}
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.libbyte :refer :all]))

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
  (->> (partition (bytes-per-block m) bv)
       (reductions (fn [i pt] (encrypt-block m (map bit-xor i pt))) (:iv m))
       (rest)
       (reduce into)))

(defmethod decrypt-blocks :cbc [m bv]
  (let [ctblocks (partition (bytes-per-block m) bv)]
    (->> ctblocks
         (map (partial decrypt-block m))
         (reduce into)
         (mapv bit-xor (reduce into (conj ctblocks (:iv m)))))))

(defmethod encrypt-blocks :cfb [m bv]
  (->> (partition (bytes-per-block m) bv)
       (reductions (fn [i pt] (mapv bit-xor pt (encrypt-block m i))) (:iv m))
       (rest)
       (vec)
       (reduce into)))

(defmethod decrypt-blocks :cfb [m bv]
  (->> (:iv m)
       (conj (partition (bytes-per-block m) bv))
       (map (partial encrypt-block m))
       (reduce into)
       (mapv bit-xor bv)))

(defn- process-blocks-ecb
  "Encrypt/Decrypt blocks in ECB mode"
  {:added "0.2.0"}
  [m bv encrypting]
  (->> (partition (bytes-per-block m) bv)
       (mapv (partial (if encrypting encrypt-block decrypt-block) m))
       (reduce into)))

(defmethod encrypt-blocks :ecb [m bv] (process-blocks-ecb m bv true))
(defmethod decrypt-blocks :ecb [m bv] (process-blocks-ecb m bv false))

(defn- process-blocks-ofb
  "Encrypt/Decrypt blocks in OFB mode"
  {:added "0.2.0"}
  [m bv]
  (->> (conj (partition (bytes-per-block m) bv) (:iv m))
       (reductions (fn [iv _] (encrypt-block m iv)) (:iv m))
       (rest)
       (reduce into)
       (mapv bit-xor bv)))

(defmethod encrypt-blocks :ofb [m bv] (process-blocks-ofb m bv))
(defmethod decrypt-blocks :ofb [m bv] (process-blocks-ofb m bv))

(defn- encrypt-block-pcbc
  "Encrypt a block in PCBC mode"
  {:added "0.2.0"}
  [m]
  (fn [[iv ct] block]
    (let [encrypted (encrypt-block m (mapv bit-xor iv block))
          ciphertext (reduce conj ct encrypted)]
      [(mapv bit-xor block encrypted) ciphertext])))

(defn- decrypt-block-pcbc
  "Decrypt a block in PCBC mode"
  {:added "0.2.0"}
  [m]
  (fn [[iv pt] block]
    (let [decrypted (decrypt-block m block)
          plaintext (mapv bit-xor iv decrypted)]
      [(mapv bit-xor block plaintext) (reduce conj pt plaintext)])))

(defn- process-blocks-pcbc
  "Encrypt/decrypt blocks in PCBC mode"
  {:added "0.2.0"}
  [m bv encrypting]
  (let [efn (if encrypting (encrypt-block-pcbc m) (decrypt-block-pcbc m))]
    (->> (partition (bytes-per-block m) bv)
         (reduce efn [(:iv m) []])
         (last))))

(defmethod encrypt-blocks :pcbc [m bv] (process-blocks-pcbc m bv true))
(defmethod decrypt-blocks :pcbc [m bv] (process-blocks-pcbc m bv false))

(defn- nonce-seq
  "Generate a lazy sequence of nonces for a given IV."
  {:added "0.2.0"}
  [iv]
  (map (partial xor (bytes->val iv)) (range)))

(defn- expand
  "Prepend the given vector with 0's out to length n"
  {:added "0.2.0"}
  [bv n]
  (into (vec (take n (repeat 0))) bv))

(defn- nonces
  "Grab n nonces from the nonce sequence for the given IV."
  {:added "0.2.0"}
  [n iv]
  (map #(expand % (- (count iv) (count %)))
       (map val->bytes (take n (nonce-seq iv)))))

(defn- process-blocks-ctr
  "Encrypt/decrypt blocks in Counter (CTR) mode."
  {:added "0.2.0"}
  [m bv]
  (let [blocks (partition (bytes-per-block m) bv)]
    (->> blocks
         (map (fn [nonce b] (mapv bit-xor b (encrypt-block m nonce)))
              (nonces (count blocks) (:iv m)))
         (reduce into))))

(defmethod encrypt-blocks :ctr [m bv] (process-blocks-ctr m bv))
(defmethod decrypt-blocks :ctr [m bv] (process-blocks-ctr m bv))