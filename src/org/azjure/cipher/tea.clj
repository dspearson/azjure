;; ## TEA
;; Tiny Encryption Algorithm

(ns org.azjure.cipher.tea
  (:require [org.azjure.cipher.blockcipher :refer [BlockCipher]]
            [org.azjure.cipher.cipher :refer [Cipher]]
            [org.azjure.libbyte :refer :all]
            [org.azjure.libcrypt :refer :all]))

(def ^{:doc "Golden ratio remainder."}
  delta 0x9E3779B9)

(defn- ^{:doc "TEA encryption"}
  tea [sum enc]
  (fn [[w0 w1 w2 w3]]
    ((if enc +modw -modw) w0
     (bit-xor (+modw (bsl32 w1 4) w2)
              (+modw w1 sum)
              (+modw (bsr32 w1 5) w3)))))

(defn- ^{:doc "Encipher round"}
  encipher-round [[a b c d]]
  (fn [[y z] round]
    (let [teafn (tea (*modw (inc round) delta) true)
          ny (teafn [y z a b])]
      [ny (teafn [z ny c d])])))

(defn- ^{:doc "Decipher round"}
  decipher-round [[a b c d]]
  (fn [[y z] round]
    (let [teafn (tea (*modw (inc round) delta) false)
          nz (teafn [z y c d])]
      [(teafn [y nz a b]) nz])))

(defn- ^{:doc "TEA cipher algorithm"}
  cipher
  ([bytes key enc]
   {:pre [(vector? bytes) (vector? key)
          (= (count bytes) 8) (= (count key) 16)]}
   (let [c-words (mapv bytes-word (partition 4 bytes))
         key-words (mapv bytes-word (partition 4 key))
         rng (if enc (range 32) (range 31 -1 -1))
         roundfn (if enc (encipher-round key-words) (decipher-round key-words))]
     (reduce roundfn c-words rng))))

;; ### TEA
;; Extend the Cipher and BlockCipher thorough the TEA record type

(defrecord TEA []
  Cipher
  (initialize [_ {:keys [key] :as initmap}]
    initmap)
  (keysizes-bytes [_]
    [16])
  BlockCipher
  (encrypt-block [_ bytes {:keys [key] :as initmap}]
    (reduce into (mapv word-bytes (cipher (vec bytes) key true))))
  (decrypt-block [_ bytes {:keys [key] :as initmap}]
    (reduce into (mapv word-bytes (cipher (vec bytes) key false))))
  (blocksize [_] 64))
