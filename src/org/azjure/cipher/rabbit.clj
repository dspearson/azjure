;; ## Rabbit
;;
;; [Rabbit]: http://tools.ietf.org/rfc/rfc4503.txt
;; Designed to meet the [Rabbit Spec][Rabbit]

(ns org.azjure.cipher.rabbit
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            [org.azjure.libcrypt :refer (+modw to-hex)]
            [org.azjure.libbyte :refer :all]))

(def ^{:doc "The maximum keystream length in bytes"} max-stream-length-bytes
  (expt 2 70))

(def initial-state [[][] 0])

(def avec [0x4D34D34D 0xD34D34D3 0x34D34D34 0x4D34D34D 
           0xD34D34D3 0x34D34D34 0x4D34D34D 0xD34D34D3])

(defn +mod8 [a b]
  (mod (+ a b) 8))

(defn ^{:doc "Adds two 32-bit values mod 2^32 and squares them generating
a 64-bit result."} square
  [w1 w2]
  (.longValue (bigint (expt (+modw w1 w2) 2))))

(defn gfn ^{:doc "Take two 32-bit values and generate one 32-bit value."} 
  [w1 w2]
  (let [sqr (square w1 w2)]
    (bit-xor (bit-and (bit-shift-right sqr 32) 0xFFFFFFFF) 
             (bit-and sqr 0xFFFFFFFF))))

(defn- gfn-round [x c]
  (fn [g round]
    (conj g (gfn (nth x round) (nth c round)))))

(defn- counter-system-round [[c b] round]
  (let [t (+ (nth c round) (nth avec round) b)
        b (bit-shift-right t 32)] 
    [(assoc c round (bit-and t 0xFFFFFFFF)) b]))

(defn- update-counter-system [[x c b] _]
  (let [uc (reduce counter-system-round [c b] (range 8))]
  [x (first uc) (last uc)]))

(defn- ns-even [g]
  (fn [[i0 i1 i2]]
    (+modw (nth g i0) (<<< (nth g i1) 16) (<<< (nth g i2) 16))))

(defn- ns-odd [g]
  (fn [[i0 i1 i2]]
    (+modw (nth g i0) (<<< (nth g i1) 8) (nth g i2))))

(defn next-state [[x c b]]
  (let [g (reduce (gfn-round x c) [] (range 8))
        evenfn (ns-even g)
        oddfn (ns-odd g)]
    [[(evenfn [0 7 6])
      (oddfn  [1 0 7])
      (evenfn [2 1 0])
      (oddfn  [3 2 1])
      (evenfn [4 3 2])
      (oddfn  [5 4 3])
      (evenfn [6 5 4])
      (oddfn  [7 6 5])] c b]))

(defn- expand-key-round [key]
  (fn [[x c b] round]
    (if (even? round)
      [(conj x (into (nth key (+mod8 round 1)) (nth key round)))
       (conj c (into (nth key (+mod8 round 4)) (nth key (+mod8 round 5))))
       b]
      [(conj x (into (nth key (+mod8 round 5)) (nth key (+mod8 round 4))))
       (conj c (into (nth key round) (nth key (+mod8 round 1))))
       b])))

(defn- bytes-word-x [state]
  (mapv bytes-word (first state)))

(defn- bytes-word-c [state]
  (mapv bytes-word (second state)))

(defn- identity-b [state]
  (identity (last state)))

(defn- expand-key [key]
  (let [kvec (mapv vec (reverse (partition 2 key)))]
    (-> (expand-key-round kvec)
        (reduce initial-state (range 8))
        ((juxt bytes-word-x bytes-word-c identity-b)))))

(defn- state-xor-round [[x c b] round]
  [x (assoc c round (bit-xor (nth c round) (nth x (+mod8 round 4)))) b])

(defn- state-xor [state]
  (reduce state-xor-round state (range 8)))

(defn- mod-counters [state iv]
  state)

(defn- setup-iv [state iv]
  (if (nil? iv) state (mod-counters state iv)))

(defn print-state [state]
  (println "State: " ((juxt #(mapv to-hex (first %)) #(mapv to-hex (second %)) #(to-hex (last %) 1)) state)))

;; ### Rabbit
;; Extend the StreamCipher and Cipher protocol thorough the Rabbit record type
(defrecord Rabbit []
  Cipher
  (initialize [_ {:keys [key iv upper] :or [upper 1024] :as initmap}]
    (let [ms (-> (comp next-state update-counter-system)
                 (reduce (expand-key key) (range 4))
                 (state-xor))
          ss (setup-iv ms iv)] 
      {:ms ms :ss ss}))
  (keysizes-bytes [_] [16])
  StreamCipher
  (generate-keystream [_ initmap [lower upper :as range]])
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 8))
