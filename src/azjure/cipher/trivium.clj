;; [TRI]: http://cr.yp.to/streamciphers/trivium/desc.pdf

(ns azjure.cipher.trivium
  "## Trivium Stream Cipher

  Implemented to meet the spec at [http://cr.yp.to/streamciphers/trivium/desc.pdf]
  [TRI]"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.cipher.streamcipher :refer :all]
            [azjure.libbyte :refer [byte->bits bits->byte]]))

(def ^{:private true
       :added   "0.2.0"}
  key-sizes
  "#### key-sizes
  Trivium supports a key of 80 bits."
  [80])

(def ^{:private true
       :added   "0.2.0"}
  iv-size
  "#### iv-size
  Trivium supports an IV (nonce) size of 80-bits."
  80)

(def ^{:private true
       :added   "0.2.0"}
  keystream-size
  "#### keystream-size
  Trivium can generate 2<sup>64</sup> keystream bytes with the same key and
  nonce"
  "2^64")

(defn- x-ones
  "### x-ones
  Generate a vector of `x` ones."
  {:added "0.2.0"}
  [x]
  (vec (take x (repeat 1))))

(defn- x-zeros
  "### x-zeros
  Generate a vector of `x` zeros."
  [x]
  (vec (take x (repeat 0))))


(defn- initialize-state
  "### initialize-state
  Initialize the Trivium state with the 80-bit key and 80-bit IV."
  [key iv]
  (let [lower (into (reduce into (mapv byte->bits (reverse key))) (x-zeros 13))
        mid (into (reduce into (mapv byte->bits (reverse iv))) (x-zeros 4))
        upper (into (x-zeros 108) (x-ones 3))]
    [lower mid upper]))

(defn- calc-tx
  "### calc-tx
  Calculate a t-value given indices into the state vector."
  [[idx0 idx1 idx2 idx3 idx4] state]
  (bit-xor (nth state idx0)
           (bit-and (nth state idx1) (nth state idx2))
           (nth state idx3)
           (nth state idx4)))

(defn- rotate 
  "### rotate
  Rotate a state vector."
  [bit bitseq]
  (vec (conj (drop-last bitseq) bit)))

(defn- rotate-all
  "Rotate all 3 state vectors."
  [t1 t2 t3 state]
  [(rotate t3 (first state))
   (rotate t1 (second state))
   (rotate t2 (last state))])

(defn- starting-state-round
  "### starting-state-round
  A Trivium starting state calculation round."
  [state round]
  (let [asone (reduce into state)
        t1 (calc-tx [65 90 91 92 170] asone)
        t2 (calc-tx [161 174 175 176 263] asone)
        t3 (calc-tx [242 285 286 287 68] asone)]
    (rotate-all t1 t2 t3 state)))

(defn- calc-new-t
  "### calc-new-t
  Calculate a new t-value from the state during encryption."
  [t [idx0 idx1 idx2] state]
  (bit-xor t
           (bit-and (nth state idx0) (nth state idx1))
           (nth state idx2)))

(defn- key-stream-round
  "### key-stream-round
  A key stream generation round.  Generates 1-bit of key stream."
  [[state out] round]
  (let [asone (reduce into state)
        t1 (bit-xor (nth asone 65) (nth asone 92))
        t2 (bit-xor (nth asone 161) (nth asone 176))
        t3 (bit-xor (nth asone 242) (nth asone 287))
        outbit (bit-xor t1 t2 t3)
        nt1 (calc-new-t t1 [90 91 170] asone)
        nt2 (calc-new-t t2 [174 175 263] asone)
        nt3 (calc-new-t t3 [285 286 68] asone)]
    [(rotate-all nt1 nt2 nt3 state)
     (conj out outbit)]))

(defn- key-stream
  "### key-stream
  Generate `x` bits of key stream."
  [x state]
  (reduce key-stream-round [state []] (range x)))

(defn- starting-state
  "### starting-state
  Generate the Trivium starting state, given the initial state."
  [state]
  (reduce starting-state-round state (range 1152)))

(defn- trivium [key iv xs]
  (let [rounds (* 8 (count xs))]
    (->> (initialize-state key iv)
         (starting-state)
         (key-stream rounds)
         (last)
         (partition 8)
         (mapv bits->byte))))

(defmethod initialize :trivium [m] m)
(defmethod keysizes-bits :trivium [_] key-sizes)
(defmethod iv-size-bits :trivium [_] iv-size)
(defmethod keystream-size-bytes :trivium [_] keystream-size)
(defmethod generate-keystream :trivium [m xs]
  (trivium (:key m) (:iv m) xs))
