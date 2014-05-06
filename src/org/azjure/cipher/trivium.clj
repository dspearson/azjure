;; ## Trivium
;;
;; [TRI]: http://www.ecrypt.eu.org/stream/ciphers/trivium/trivium.pdf
;; Designed to meet the [Trivium Spec][TRI]

(ns org.azjure.cipher.trivium
  (:require [clojure.math.numeric-tower :refer [expt]]
            [org.azjure.cipher.cipher :refer [Cipher]]
            [org.azjure.cipher.streamcipher :refer [StreamCipher]]
            [org.azjure.libbyte :refer :all]
            [org.azjure.libcrypt :refer [bytes->keyword]]))

(def ^{:doc "Trivium key streams."}
  trivium-key-streams (atom {}))

(def ^{:doc "The maximum keystream length in bytes"}
  max-stream-length-bytes (expt 2 61))

(defn- ^{:doc "Generate a vector of x ones."}
  x-ones [x]
  (vec (take x (cycle [1]))))

(defn- ^{:doc "Generate a vector of x zeros."}
  x-zeros [x]
  (vec (take x (cycle [0]))))

(defn- ^{:doc "Initialize the trivium state with the key and IV."}
  initialize-state [key iv]
  (let [lower (into (reduce into (mapv byte->bits (reverse key))) (x-zeros 13))
        mid (into (reduce into (mapv byte->bits (reverse iv))) (x-zeros 4))
        upper (into (x-zeros 108) (x-ones 3))]
    [lower mid upper]))

(defn- ^{:doc "Calculate a t-value given indices into the state vector."}
  calc-tx [[idx0 idx1 idx2 idx3 idx4] state]
  (bit-xor (nth state idx0)
           (bit-and (nth state idx1) (nth state idx2))
           (nth state idx3)
           (nth state idx4)))

(defn- ^{:doc "Rotate a state vector."}
  rotate [bit bitseq]
  (vec (conj (drop-last bitseq) bit)))

(defn- ^{:doc "Rotate all 3 state vectors."}
  rotate-all [t1 t2 t3 state]
  [(rotate t3 (first state))
   (rotate t1 (second state))
   (rotate t2 (last state))])

(defn- ^{:doc "A Trivium starting state calculation round."}
  starting-state-round [state round]
  (let [asone (reduce into state)
        t1 (calc-tx [65 90 91 92 170] asone)
        t2 (calc-tx [161 174 175 176 263] asone)
        t3 (calc-tx [242 285 286 287 68] asone)]
    (rotate-all t1 t2 t3 state)))

(defn- ^{:doc "Generate the Trivium starting state, given
the initial state."}
  starting-state [state]
  (reduce starting-state-round state (range 1152)))

(defn- ^{:doc "Calculate a new t-value from the state during encryption."}
  calc-new-t [t [idx0 idx1 idx2] state]
  (bit-xor t
           (bit-and (nth state idx0) (nth state idx1))
           (nth state idx2)))

(defn- ^{:doc "A key stream generation round.  Generates 1-bit of key stream."}
  key-stream-round [[state out] round]
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

(defn- ^{:doc "Generate x bits of key stream."}
  key-stream [x state]
  (reduce key-stream-round [state []] (range x)))

(defn- ^{:doc "Reset the state at uid in the keystreams atom."}
  resetks!
  ([uid]
   {:pre [(keyword? uid)]}
   (swap! trivium-key-streams assoc uid {})))

(defn- ^{:doc "Swap any existing keystream in the keystream atom at :uid
with a newly generated one."}
  swapks!
  ([key iv uid [lower upper]]
   {:pre [(vector? key) (vector? iv) (keyword? uid)
          (= 10 (count key)) (= 10 (count iv))
          (< upper max-stream-length-bytes)]}
   (let [rounds (* 8 upper)                                 ; Each round generates 1-bit.
         out (->> (initialize-state key iv)
                  (starting-state)
                  (key-stream rounds)
                  (last)
                  (partition 8)
                  (mapv bits->byte))]
     (swap! trivium-key-streams assoc uid {:ks out :upper upper}))))

;; ### Trivium
;; Extend the StreamCipher and Cipher protocol thorough the Trivium record type.

(defrecord Trivium []
  Cipher
  ;; Initialize will, by default, generate 1024 bytes (8192 bits) of keystream.  
  ;; This can be increased or decreased by supplying :upper X in the initmap 
  ;; along with :key and :iv. Evaluates to a map 
  ;; {:key key :iv iv :upper upper :uid uid} to be used with generate-keystream.
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [uid (bytes->keyword (into key iv))]
      (do
        (resetks! uid)
        (swapks! key iv uid [0 upper]))
      (assoc initmap :uid uid)))
  (keysizes-bytes [_] [10])
  StreamCipher
  ;; If upper is larger than the current upper bound of the keystream in the
  ;; state map at the given uid, then new keystream is generated and stored.
  ;; The result is always a subvector of the keystream stored with the state map
  ;; at :uid.
  (generate-keystream [_ {:keys [key iv uid lower upper]} _]
    (when (>= (dec upper) (:upper (uid @trivium-key-streams)))
      (resetks! uid)
      (swapks! key iv uid [0 upper]))
    (subvec (:ks (uid @trivium-key-streams)) lower upper))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 10))
