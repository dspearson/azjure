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

(def ^{:doc "Used to store keystreams data by key"} rabbit-key-streams
  (atom {}))

;;     {:key    {:ms [] :ss [] :upper val :ks []}
;;      :keyiv0 {:ms [] :ss [] :upper val :ks []}
;;      :keyiv1 {:ms [] :ss [] :upper val :ks []}}
;;
;; Note that all the ms vectors would be the same in this case as the master
;; state for key serves as the master state for any following key/iv pair
;; that uses the same key.

(def ^{:doc "The maximum keystream length in bytes"} max-stream-length-bytes
  (expt 2 70))

(def initial-state [[][] 0])

(def avec [0x4D34D34D 0xD34D34D3 0x34D34D34 0x4D34D34D 
           0xD34D34D3 0x34D34D34 0x4D34D34D 0xD34D34D3])

(defn +mod8 [a b]
  (mod (+ a b) 8))

(defn- ^{:doc "Adds two 32-bit values mod 2^32 and squares them generating
a 64-bit result."} square
  [w1 w2]
  (.longValue (bigint (expt (+modw w1 w2) 2))))

(defn- gfn ^{:doc "Take two 32-bit values and generate one 32-bit value."} 
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

(defn- next-state [[x c b]]
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

(defn- xor-counter [c ivec]
  (fn [[cidx iidx0 iidx1]]
    (->> (into (nth ivec iidx0) (nth ivec iidx1))
         (bytes-word)
         (bit-xor (nth c cidx)))))

(defn- update-counter [iv]
  (fn [c round]
    (let [xfn (xor-counter c iv)]
      (->> (condp = (mod round 4)
             0 (xfn [round 1 0])
             1 (xfn [round 3 1])
             2 (xfn [round 3 2])
             3 (xfn [round 2 0]))
           (assoc c round)))))

(defn- mod-counters [[x c b] iv]
  (let [ivec (mapv vec (reverse (partition 2 iv)))]
    [x (reduce (update-counter ivec) c (range 8)) b]))

(defn- ms2b [word]
  (bit-shift-right word 16))

(defn- ls2b [word]
  (bit-and word 0xFFFF))

(def roundfn (comp next-state update-counter-system))

(defn- word<-x [x]
  (fn [[idx0 idx1 idx2 idx3]]
    (bit-or
     (bit-xor (ls2b (nth x idx0)) (ms2b (nth x idx1)))
     (bit-shift-left (bit-xor (ms2b (nth x idx2)) (ls2b (nth x idx3))) 16))))

(defn- rabbit-round [{:keys [ss out] :as initmap} r]
  (let [[xn cn bn] (roundfn ss 0)
        exfn (word<-x xn)]
    (assoc initmap 
      :ss [xn cn bn]
      :out (->> [(exfn [6 3 6 1])
                 (exfn [4 1 4 7])
                 (exfn [2 7 2 5])
                 (exfn [0 5 0 3])]
                (into out)))))

(defn- ^{:doc "Generate a keyword from the 
given vector of bytes."} bytes->keyword
  [bytes]
  (-> (->> (partition 4 bytes)
           (mapv (comp to-hex bytes-word))
           (reduce str))
      (clojure.string/replace #"0x" "")
      (keyword)))

(defn- master-state [baseuid uid key]
  (if (contains? @rabbit-key-streams baseuid)
    (:ms (baseuid @rabbit-key-streams))
    (if (contains? @rabbit-key-streams uid)
      (:ms (uid @rabbit-key-streams))
      (-> roundfn
          (reduce (expand-key key) (range 4))
          (state-xor)))))

(defn- starting-state [uid ms iv]
  (if (nil? iv)
    ms
    (reduce roundfn (mod-counters ms iv) (range 4))))

(defn- resetstate! [key iv resetkw]
  (let [basekw (bytes->keyword key)
        ms (master-state basekw resetkw key)]
    (if-not (contains? @rabbit-key-streams basekw)
      (swap! rabbit-key-streams assoc basekw 
             {:ms ms :ss (starting-state basekw ms nil)}))
    (swap! rabbit-key-streams assoc resetkw
           {:ms ms :ss (starting-state resetkw ms iv)})))

(defn- swapks! [keykw [lower upper :as bounds]]
  (let [rounds (inc (quot upper 16))
        rounds (if (zero? (rem upper 16)) rounds (inc rounds))
        statemap (keykw @rabbit-key-streams)
        out (reduce rabbit-round (conj {:out []} statemap) (range rounds))]
    (swap! rabbit-key-streams assoc keykw
           (assoc (keykw @rabbit-key-streams) 
             :ss (:ss out) 
             :upper upper 
             :ks (reduce into (mapv word-bytes (:out out)))))))

;; ### Rabbit
;; Extend the StreamCipher and Cipher protocol thorough the Rabbit record type
(defrecord Rabbit []
  Cipher
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [kivb (if (nil? iv) key (into key iv))
          keykw (bytes->keyword kivb)]
      (do
        (resetstate! key iv keykw)
        (swapks! keykw [0 upper]))
      (assoc initmap :upper upper :keykw keykw)))
  (keysizes-bytes [_] [16])
  StreamCipher
  (generate-keystream [_ {:keys [key iv keykw]} [lower upper :as bounds]]
    (when (>= (dec upper) (:upper (keykw @rabbit-key-streams)))
      (resetstate! key iv keykw)
      (swapks! keykw [0 upper]))
    (subvec (:ks (keykw @rabbit-key-streams)) lower upper))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 8))
