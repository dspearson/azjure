;; ## Counter Mode
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining#Counter_.28CTR.29)
;; > "Like OFB, counter mode turns a block cipher into a stream cipher.
;; > It generates the next keystream block by encrypting successive values of a 'counter'."
;;
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.ctr
  (:require [clojure.core.reducers :as r]
            [net.ozias.crypt.libbyte :refer (dword-bytes)]
            [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
            [net.ozias.crypt.cipher.streamcipher :as sc]
            [net.ozias.crypt.cipher.twofish :refer (->Twofish)]))

(defn- pad-iv [cipher iv ctr]
  (let [diff (- (sc/iv-size-bytes cipher) (count iv))]
    (reduce conj iv (take diff (dword-bytes ctr)))))

(defn- process-bytes [cipher key iv bytes]
  (let [len (count bytes)
        kb (sc/keystream-size-bytes cipher)
        ks (if (not (zero? (rem len kb))) (inc (quot len kb)) (quot len kb))]
    (->> (range (inc ks))
         (r/map (partial pad-iv cipher iv))
         (r/map (partial sc/generate-keystream cipher key))
         (into [])
         (reduce into)
         (mapv bit-xor bytes))))

;; ### CounterMode
;; Extend the ModeOfOperation protocol through the CounterMode record.
(defrecord CounterMode []
  ModeOfOperation
  (encrypt [_ cipher iv bytes key]
    (process-bytes cipher key iv bytes))
  (decrypt [_ cipher iv bytes key]
    (process-bytes cipher key iv bytes)))

