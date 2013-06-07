;; ## Counter Mode
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining#Counter_.28CTR.29)
;; > "Like OFB, counter mode turns a block cipher into a stream cipher.
;; > It generates the next keystream block by encrypting successive values of a 'counter'."
;;
(ns ^{:author "Jason Ozias"}
  org.azjure.mode.ctr
  (:require [clojure.core.reducers :as r]
            [org.azjure.libbyte :refer (dword-bytes)]
            [org.azjure.mode.modeofoperation :refer [ModeOfOperation]]
            [org.azjure.cipher.streamcipher :as sc]))

;; ### pad-iv
;; Add the counter bytes to the IV bytes up the the size
;; of IV needed by the cipher. Currently,the counter will 
;; max out at 8 bytes.
;;
;; Evaluates to a vector of bytes.
(defn- pad-iv [cipher iv ctr]
  (let [diff (- (sc/iv-size-bytes cipher) (count iv))]
    (reduce conj iv (take diff (dword-bytes ctr)))))

;; ### process-bytes
;; Process the given byte vector with the given cipher,
;; key, and IV.
;;
;; Evaluates to a vector of bytes.
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
  (encrypt [_ cipher key iv bytes]
    (process-bytes cipher key iv bytes))
  (decrypt [_ cipher key iv bytes]
    (process-bytes cipher key iv bytes)))

