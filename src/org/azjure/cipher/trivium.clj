;; ## Trivium
;;
;; [TRI]: http://www.ecrypt.eu.org/stream/ciphers/trivium/trivium.pdf
;; Designed to meet the [Trivium Spec][TRI]
(ns org.azjure.cipher.trivium
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            [org.azjure.libcrypt :refer (to-hex)]
            [org.azjure.libbyte :refer :all]))

(def ^{:doc "The maximum keystream length in bytes"}
  max-stream-length-bytes (expt 2 61))

(def initial-state [])

(defn- x-ones [x]
  (vec (take x (cycle [1]))))

(defn- x-zeros [x]
  (vec (take x (cycle [0]))))

(defn- initialize-state [key iv]
  (let [lower (into (reduce into (mapv byte->bits key)) (x-zeros 13))
        mid (into (reduce into (mapv byte->bits iv)) (x-zeros 4))
        upper (into (x-zeros 108) (x-ones 3))]
    [lower mid upper]))

(defn- calc-tx [[idx0 idx1 idx2 idx3 idx4] state]
  (bit-xor (nth state idx0)
           (bit-and (nth state idx1) (nth state idx2))
           (nth state idx3)
           (nth state idx4)))

(defn- rotate [bit bitseq]
  (vec (conj (drop-last bitseq) bit)))

(defn- rotate-all [t1 t2 t3 state]
  [(rotate t3 (first state))
   (rotate t1 (second state))
   (rotate t2 (last state))])

(defn- starting-state-round [state round]
  (let [asone (reduce into state)
        t1 (calc-tx [65  90  91  92  170] asone)
        t2 (calc-tx [161 174 175 176 263] asone)
        t3 (calc-tx [242 285 286 287 68 ] asone)]
    (rotate-all t1 t2 t3 state)))

(defn- starting-state [state]
  (reduce starting-state-round state (range 1152)))

(defn- calc-new-t [t [idx0 idx1 idx2] state]
  (bit-xor
   t
   (bit-and (nth state idx0)(nth state idx1))
   (nth state idx2)))

; t1 = s66 + s93
; t2 = s162 + s177
; t3 = s243 + s288
; zi = t1 + t2 + t3
; t1 = t1 + s91 * s92 + s171
; t2 = t2 + s175 * s176 + s264
; t3 = t3 + s286 * s287 + s69
(defn- key-stream-round [[state out] round]
  (let [asone (reduce into state)
        t1 (bit-xor (nth asone 65)(nth asone 92))
        t2 (bit-xor (nth asone 161)(nth asone 176))
        t3 (bit-xor (nth asone 242)(nth asone 287))
        outbit (bit-xor t1 t2 t3)
        nt1 (calc-new-t t1 [90  91  170] asone) 
        nt2 (calc-new-t t2 [174 175 263] asone)
        nt3 (calc-new-t t3 [285 286  68] asone)]
    [(rotate-all nt1 nt2 nt3 state)
     (conj out outbit)]))

(defn- key-stream [state bound]
  (reduce key-stream-round [state []] (range bound)))

;; ### Trivium
;; Extend the StreamCipher and Cipher protocol thorough the Trivium record type.

(defrecord Trivium []
  Cipher
  ;; Initialize will, by default, generate 1024 bytes of keystream.  This can be
  ;; increased or decreased by supplying :upper X in the initmap along with :key
  ;; and :iv. Evaluates to a map {:key key :iv iv :upper upper :uid uid} to be
  ;; used with generate-keystream.
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    ;(let [uid (bytes->keyword (if (nil? iv) key (into key iv)))]
    ;  (do
    ;    (resetstatemap! key iv uid)
    ;    (swapstatemapks! uid [0 upper]))
    ;  (assoc initmap :uid uid)
    ;(mapv bits->byte (partition 8 (last (key-stream (starting-state (initialize-state key iv)))))))
    (last (key-stream (starting-state (initialize-state key iv)) (* 8 upper))))
  (keysizes-bytes [_] [10])
  StreamCipher
  ;; If upper is larger than the current upper bound of the keystream in the
  ;; state map at the given uid, then new keystream is generated and stored.
  ;; The result is always a subvector of the keystream stored with the state map
  ;; at :uid.
  (generate-keystream [_ {:keys [key iv uid lower upper]} _]
    ;(when (>= (dec upper) (:upper (uid @state-maps)))
    ;  (resetstatemap! key iv uid)
    ;  (swapstatemapks! uid [0 upper]))
    ;(subvec (:ks (uid @state-maps)) lower upper))
    )
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 10))
