(ns azjure.cipher.salsa20-spec
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.core :refer [encrypted-stream]]
            [azjure.encoders :refer :all]
            [azjure.libtest :refer :all]
            [clojure.java.io :as io]
            [speclj.core :refer :all]))

;"https://raw.githubusercontent.com/alexwebr/salsa20/master/test_vectors.128")
(def ^{:private true}
  salsa20-test-vectors-text (io/file (io/resource "tv128.txt")))
(def ^{:private true} sep '("====================="))

(defn- parse-range [r]
  (let [[lower upper] (clojure.string/split
                        (->> r
                             (remove #(= \[ %))
                             (remove #(= \] %))
                             (apply str))
                        #"\.\.")]
    {:upper (Integer/parseInt upper)
     :lower (Integer/parseInt lower)}))

(defn- parse-subvecs [s]
  (for [[range hex] (->> (clojure.string/split
                           (->> s
                                (take-while #(not (.startsWith % "xor-digest")))
                                (clojure.string/join)) #"stream")
                         (rest)
                         (map #(clojure.string/split % #" = ")))]
    (conj {:value (vec (hex->xs hex))}
          (parse-range range))))

(defn parse-tvs []
  (let [lines (clojure.string/split (slurp salsa20-test-vectors-text) #"\n")]
    (for [[key iv & sv] (->> lines
                             (map clojure.string/trim)
                             (partition-by #(.startsWith % "Test vectors"))
                             (take-nth 2)
                             (map (partial remove empty?))
                             (map (partial partition-by #(.startsWith % "Set")))
                             (map (partial remove #(= sep %)))
                             (map rest)
                             (map (partial take-nth 2))
                             (reduce into)
                             (reverse))]
      {:key     (vec (hex->xs (last (clojure.string/split key #" "))))
       :nonce   (vec (hex->xs (last (clojure.string/split iv #" "))))
       :subvecs (vec (parse-subvecs sv))})))

(def ^{:private true
       :doc     "Configuration Map"}
  cm {:type :salsa20})

(def ^{:private true
       :doc     "512-bytes of 0"}
  zeros-512
  (take 512 (repeat 0)))

(def ^{:private true
       :doc     "131072 bytes of 0"}
  zeros-131072
  (take 131072 (repeat 0)))

(defn max-upper [subvecs]
  (apply max (map :upper subvecs)))

(describe
  "Salsa20"
  (check-keysizes cm [128 256])
  (check-iv-size-bits cm 64)
  (check-keystream-size-bytes cm "2^70")

  (for [{:keys [key nonce subvecs]} (parse-tvs)]
    (context
      "test vectors"
      (with s20pt (if (= (max-upper subvecs) 511) zeros-512 zeros-131072))
      (with s20cm (initialize (assoc cm :key key :nonce nonce)))
      (with ks (vec (encrypted-stream @s20pt @s20cm)))

      (for [{:keys [lower upper value]} subvecs]
        (context
          "test subvectors"
          (it "should be encrypted to propert ciphertext"
              (should= value (subvec @ks lower (inc upper))))))

      (it "should decrypt to the proper cleartext"
          (should= @s20pt (encrypted-stream @ks @s20cm))))))