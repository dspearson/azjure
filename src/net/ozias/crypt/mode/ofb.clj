;; ## Output Feedback
;; Output Feedback mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.mode.ofb
  (:require [clojure.core.reducers :as r]
            [net.ozias.crypt.mode.modeofoperation :refer [ModeOfOperation]]
            [net.ozias.crypt.cipher.streamcipher :as sc]))

;; ### process-bytes
;; Encrypt the given bytes vector with the given
;; cipher, key and IV.
;;
;; Evaluates to a vector of bytes.
(defn- process-bytes [cipher key iv bytes]
  (let [len (count bytes)
        kb (sc/keystream-size-bytes cipher)
        ks (if (not (zero? (rem len kb))) (inc (quot len kb)) (quot len kb))]
    (->> (range (inc ks))
         (reductions (fn [iv _] (sc/generate-keystream cipher key iv)) iv)
         (rest)
         (reduce into)
         (mapv bit-xor bytes))))

;; ### OutputFeedback
;; Extend the ModeOfOperation protocol through the OutputFeedback record.
(defrecord OutputFeedback []
  ModeOfOperation
  (encrypt [_ cipher key iv bytes]
    (process-bytes cipher key iv bytes))
  (decrypt [_ cipher key iv bytes]
    (process-bytes cipher key iv bytes)))
