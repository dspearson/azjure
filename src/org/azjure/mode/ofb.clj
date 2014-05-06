;; ## Output Feedback
;; Output Feedback mode
;;
;; [Block Cipher Mode of Operation](http://en.wikipedia.org/wiki/Cipher_block_chaining)

(ns org.azjure.mode.ofb
  {:author "Jason Ozias"}
  (:require [org.azjure.cipher.blockcipher :as bc]
            [org.azjure.mode.modeofoperation :refer [ModeOfOperation]]))

;; ### process-bytes
;; Encrypt the given bytes vector with the given
;; cipher, key and IV.
;;
;; Evaluates to a vector of bytes.
(defn- process-bytes [cipher key iv bytes]
  (let [len (count bytes)
        kb (quot (bc/blocksize cipher) 8)
        ks (if-not (zero? (rem len kb)) (inc (quot len kb)) (quot len kb))]
    (->> (range (inc ks))
         (reductions (fn [iv _] (bc/encrypt-block cipher iv key)) iv)
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
