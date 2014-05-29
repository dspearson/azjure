(ns azjure.cipher.salsa20-spec
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.core :refer [encrypted-stream]]
            [azjure.encoders :refer :all]
            [azjure.libtest :refer :all]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [speclj.core :refer :all]))

;"https://raw.githubusercontent.com/alexwebr/salsa20/master/test_vectors.128"
(def ^{:private true}
  s20-test-vectors-128 (io/file (io/resource "s20_test_vectors_128.txt")))
;"https://raw.githubusercontent.com/alexwebr/salsa20/master/test_vectors.256"
(def ^{:private true}
  s20-test-vectors-256 (io/file (io/resource "s20_test_vectors_256.txt")))
(def ^{:private true} sep '("====================="))

(defn- parse-range [r]
  (let [[lower upper] (str/split
                        (->> r
                             (remove #(= \[ %))
                             (remove #(= \] %))
                             (apply str))
                        #"\.\.")]
    {:upper (Integer/parseInt upper)
     :lower (Integer/parseInt lower)}))

(defn- parse-subvecs [s]
  (for [[range hex] (->> (str/split
                           (->> s
                                (take-while #(not (.startsWith % "xor-digest")))
                                (str/join)) #"stream")
                         (rest)
                         (map #(str/split % #" = ")))]
    (conj {:value (vec (hex->xs hex))}
          (parse-range range))))

(defn parse-tvs-128 []
  (let [lines (str/split (slurp s20-test-vectors-128) #"\n")]
    (for [[key iv & sv] (->> lines
                             (map str/trim)
                             (remove empty?)
                             (partition-by #(.startsWith % "Set"))
                             (rest)
                             (take-nth 2))]
      {:key     (vec (hex->xs (last (str/split key #" "))))
       :nonce   (vec (hex->xs (last (str/split iv #" "))))
       :subvecs (vec (parse-subvecs sv))})))

(defn parse-tvs-256 []
  (let [lines (str/split (slurp s20-test-vectors-256) #"\n")]
    (for [[k1 k2 iv & sv] (->> lines
                               (map str/trim)
                               (remove empty?)
                               (partition-by #(.startsWith % "Set"))
                               (rest)
                               (take-nth 2))]
      {:key     (vec (hex->xs (last (str/split (str k1 k2) #" "))))
       :nonce   (vec (hex->xs (last (str/split iv #" "))))
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

  (for [{:keys [key nonce subvecs]} (parse-tvs-128)]
    (context
      "test vectors"
      (with-all s20pt (if (= (max-upper subvecs) 511) zeros-512 zeros-131072))
      (with-all s20cm (initialize (assoc cm :key key :nonce nonce)))
      (with-all ks (vec (encrypted-stream @s20pt @s20cm)))

      (for [{:keys [lower upper value]} subvecs]
        (context
          "test subvectors"
          (it "should be encrypted to propert ciphertext"
              (should= value (subvec @ks lower (inc upper))))))

      (it "should decrypt to the proper cleartext"
          (should= @s20pt (encrypted-stream @ks @s20cm)))))

  (for [{:keys [key nonce subvecs]} (parse-tvs-256)]
    (context
      "test vectors"
      (with-all s20pt1 (if (= (max-upper subvecs) 511) zeros-512 zeros-131072))
      (with-all s20cm1 (initialize (assoc cm :key key :nonce nonce)))
      (with-all ks1 (vec (encrypted-stream @s20pt1 @s20cm1)))

      (for [{:keys [lower upper value]} subvecs]
        (context
          "test subvectors"
          (it "should be encrypted to propert ciphertext"
              (should= value (subvec @ks1 lower (inc upper))))))

      (it "should decrypt to the proper cleartext"
          (should= @s20pt1 (encrypted-stream @ks1 @s20cm1)))))

  )