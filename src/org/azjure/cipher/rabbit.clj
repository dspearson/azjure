;; ## Rabbit
;;
;; [Rabbit]: http://tools.ietf.org/rfc/rfc4503.txt
;; Designed to meet the [Rabbit Spec][Rabbit]

(ns org.azjure.cipher.rabbit
  (:require [clojure.math.numeric-tower :refer [expt]]
            [org.azjure.cipher.cipher :refer [Cipher]]
            [org.azjure.cipher.streamcipher :refer [StreamCipher]]
            [org.azjure.libbyte :refer :all]
            [org.azjure.libcrypt :refer [+mod8 +modw bytes->keyword]]))

(def ^{:doc "Used to store keystreams data by key"}
  state-maps (atom {}))

;;     {:key    {:ms [] :ss [] :upper val :ks []}
;;      :keyiv0 {:ms [] :ss [] :upper val :ks []}
;;      :keyiv1 {:ms [] :ss [] :upper val :ks []}}
;;
;; Note that all the ms vectors would be the same in this case as the master
;; state for key serves as the master state for any following key/iv pair
;; that uses the same key.

(def ^{:doc "The maximum keystream length in bytes"}
  max-stream-length-bytes (expt 2 70))

(def ^{:doc "The initial state. X and C are empty vectors
and the carry bit is 0."}
  initial-state [[] [] 0])

(def ^{:doc "Constants used during a counter update."}
  avec [0x4D34D34D 0xD34D34D3 0x34D34D34 0x4D34D34D
        0xD34D34D3 0x34D34D34 0x4D34D34D 0xD34D34D3])

(defn- ^{:doc "Adds two 32-bit values mod 2^32 and squares them generating
a 64-bit result."}
  square [word1 word2]
  (.longValue (bigint (expt (+modw word1 word2) 2))))

(defn- ^{:doc "Take two 32-bit values and generate one 32-bit value."}
  gfn [word1 word2]
  (let [squared (square word1 word2)]
    (bit-xor (bit-and (bit-shift-right squared 32) 0xFFFFFFFF)
             (bit-and squared 0xFFFFFFFF))))

(defn- ^{:doc "A g-function round.  Conj's the result of gfn to the 
supplied g vector."}
  gfn-round [x c]
  (fn [g round]
    (conj g (gfn (nth x round) (nth c round)))))

(defn- ^{:doc "Update the counter vector and carry bit based
on the given round."}
  next-counters-b-round [[c b] round]
  (let [t (+ (nth c round) (nth avec round) b)
        ; Note "normal" addition above to catch carry bit if the add
        ; overflows 32 bits.
        b (bit-shift-right t 32)]
    [(assoc c round (bit-and t 0xFFFFFFFF)) b]))

(defn- ^{:doc "Update the counter vector and carry bit in the
state vector during key expansion."}
  next-counters-b [[x c b] _]
  (let [uc (reduce next-counters-b-round [c b] (range 8))]
    [x (first uc) (last uc)]))

(defn- ^{:doc "Generate a 32-bit word from indexes into the g
vector."}
  next-x-even [g]
  (fn [[i0 i1 i2]]
    (+modw (nth g i0) (<<< (nth g i1) 16) (<<< (nth g i2) 16))))

(defn- ^{:doc "Generate a 32-bit word from indexes into the g
vector."}
  next-x-odd [g]
  (fn [[i0 i1 i2]]
    (+modw (nth g i0) (<<< (nth g i1) 8) (nth g i2))))

(defn- ^{:doc "Generate the next [x c b] state."}
  next-x [[x c b]]
  (let [g (reduce (gfn-round x c) [] (range 8))
        evenfn (next-x-even g)
        oddfn (next-x-odd g)]
    [[(evenfn [0 7 6])
      (oddfn [1 0 7])
      (evenfn [2 1 0])
      (oddfn [3 2 1])
      (evenfn [4 3 2])
      (oddfn [5 4 3])
      (evenfn [6 5 4])
      (oddfn [7 6 5])] c b]))

(defn- ^{:doc "Used to convert the X vector in [x c b] from words to bytes."}
  bytes-word-x [state]
  (mapv bytes-word (first state)))

(defn- ^{:doc "Used to convert the C vector in [x c b] from words to bytes."}
  bytes-word-c [state]
  (mapv bytes-word (second state)))

(defn- ^{:doc "Used to get the carry bit out of the state [x c b]."}
  identity-b [state]
  (identity (last state)))

(defn- ^{:doc "Updates the current [x c b] state during key expansion."}
  expand-key-round [key]
  (fn [[x c b] round]
    (if (even? round)
      [(conj x (into (nth key (+mod8 round 1)) (nth key round)))
       (conj c (into (nth key (+mod8 round 4)) (nth key (+mod8 round 5))))
       b]
      [(conj x (into (nth key (+mod8 round 5)) (nth key (+mod8 round 4))))
       (conj c (into (nth key round) (nth key (+mod8 round 1))))
       b])))

(defn- ^{:doc "Expand the key into the master state [x c b]."}
  expand-key [key]
  (let [kvec (mapv vec (reverse (partition 2 key)))]
    (-> (expand-key-round kvec)
        (reduce initial-state (range 8))
        ((juxt bytes-word-x bytes-word-c identity-b)))))

(defn- ^{:doc "Updated the counters in [x c b] based on the given round."}
  update-counters-postms-round [[x c b] round]
  [x (assoc c round (bit-xor (nth c round) (nth x (+mod8 round 4)))) b])

(defn- ^{:doc "Update the counters as the final step in master state
generation."}
  update-counters-postms [state]
  (reduce update-counters-postms-round state (range 8)))

(defn- ^{:doc "xor the counter value with a word formed from two 
2-byte sections of the IV."}
  xor-counter [c ivec]
  (fn [[cidx iidx0 iidx1]]
    (->> (into (nth ivec iidx0) (nth ivec iidx1))
         (bytes-word)
         (bit-xor (nth c cidx)))))

(defn- ^{:doc "Update a counter value based on the given iv and round."}
  update-counters-pre-ss-round [iv]
  (fn [c round]
    (let [xfn (xor-counter c iv)]
      (assoc c round (condp = (mod round 4)
                       0 (xfn [round 1 0])
                       1 (xfn [round 3 1])
                       2 (xfn [round 3 2])
                       3 (xfn [round 2 0]))))))

(defn- ^{:doc "Update the counters vector before starting state calculation."}
  update-counters-pre-ss [[x c b] iv]
  (let [ivec (mapv vec (reverse (partition 2 iv)))]
    [x (reduce (update-counters-pre-ss-round ivec) c (range 8)) b]))

(defn- ^{:doc "Get the 2 most significant bytes from the given word."}
  ms2b [word]
  (bit-shift-right word 16))

(defn- ^{:doc "Get the 2 least significant bytes from the given word."}
  ls2b [word]
  (bit-and word 0xFFFF))

(def ^{:doc "Function composition that represents one Rabbit state 
transition."}
  next-state (comp next-x next-counters-b))

(defn- ^{:doc "Convert the given indices into x (a vector of bytes) 
into an output word."}
  outw<-x [x]
  (fn [[idx0 idx1 idx2 idx3]]
    (bit-or
      (bit-xor (ls2b (nth x idx0)) (ms2b (nth x idx1)))
      (bit-shift-left (bit-xor (ms2b (nth x idx2)) (ls2b (nth x idx3))) 16))))

(defn- ^{:doc "Represents one Rabbit round.  This will update the initmap
with the current starting state for the next round (:ss), and will place
the 128-bits (as four 32-bit words) of generated keystream into :out."}
  rabbit-round [{:keys [ss out] :as initmap} r]
  (let [[xn cn bn] (next-state ss 0)
        exfn (outw<-x xn)]
    (assoc initmap
      :ss [xn cn bn]
      :out (into out [(exfn [6 3 6 1])
                      (exfn [4 1 4 7])
                      (exfn [2 7 2 5])
                      (exfn [0 5 0 3])]))))

(defn- ^{:doc "Evaluates to the master state.  The master state is
based soley on the key, so only needs to be calculated for new key
values.  If a master state is found at the baseuid, that is used.
If a master state is found at the current uid is found, that is used.
Otherwise, a new master state is calculated."}
  master-state [baseuid uid key]
  (if (contains? @state-maps baseuid)
    (:ms (baseuid @state-maps))
    (if (contains? @state-maps uid)
      (:ms (uid @state-maps))
      (-> next-state
          (reduce (expand-key key) (range 4))
          (update-counters-postms)))))

(defn- ^{:doc "Evaluates to the starting state. If no initialization
vector is supplied the starting state is the master state.  Otherwise,
the starting state is calculated based upon the initialization vector."}
  starting-state [uid ms iv]
  (if (nil? iv)
    ms
    (reduce next-state (update-counters-pre-ss ms iv) (range 4))))

(defn- ^{:doc "Reset the state at uid in the state-maps atom.  If no
state map exists at :baseuid one will be generated for efficiencies
with new IVs for the same key.  Then reset the statemap at :uid."}
  resetstatemap!
  ([key iv uid]
   {:pre [(vector? key) (keyword? uid)
          (or (nil? iv) (vector? iv))
          (= 16 (count key))
          (or (nil? iv) (= 8 (count iv)))]}
   (let [baseuid (bytes->keyword key)
         ms (master-state baseuid uid key)]
     (if-not (contains? @state-maps baseuid)
       (swap! state-maps assoc baseuid
              {:ms ms :ss (starting-state baseuid ms nil)}))
     (swap! state-maps assoc uid
            {:ms ms :ss (starting-state uid ms iv)}))))

(defn- ^{:doc "Swap any existing keystream in the state map at :uid with
a newly generated one."}
  swapstatemapks!
  ([uid [lower upper]]
   {:pre [(< upper max-stream-length-bytes)]}
   (let [rounds (inc (quot upper 16))                       ; Each round generates 16-bytes (128-bits)
         rounds (if (zero? (rem upper 16)) rounds (inc rounds))
         statemap (uid @state-maps)
         out (reduce rabbit-round (conj {:out []} statemap) (range rounds))]
     (swap! state-maps assoc uid
            (assoc (uid @state-maps)
              :ss (:ss out)
              :upper upper
              :ks (reduce into (mapv word-bytes (:out out))))))))

;; ### Rabbit
;; Extend the StreamCipher and Cipher protocol thorough the Rabbit record type.

(defrecord Rabbit []
  Cipher
  ;; Initialize will, by default, generate 1024 bytes of keystream.  This can be
  ;; increased or decreased by supplying :upper X in the initmap along with :key
  ;; and :iv. Evaluates to a map {:key key :iv iv :upper upper :uid uid} to be
  ;; used with generate-keystream.
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [uid (bytes->keyword (if (nil? iv) key (into key iv)))]
      (do
        (resetstatemap! key iv uid)
        (swapstatemapks! uid [0 upper]))
      (assoc initmap :uid uid)))
  (keysizes-bytes [_] [16])
  StreamCipher
  ;; If upper is larger than the current upper bound of the keystream in the
  ;; state map at the given uid, then new keystream is generated and stored.
  ;; The result is always a subvector of the keystream stored with the state map
  ;; at :uid.
  (generate-keystream [_ {:keys [key iv uid lower upper]} _]
    (when (>= (dec upper) (:upper (uid @state-maps)))
      (resetstatemap! key iv uid)
      (swapstatemapks! uid [0 upper]))
    (subvec (:ks (uid @state-maps)) lower upper))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 8))
