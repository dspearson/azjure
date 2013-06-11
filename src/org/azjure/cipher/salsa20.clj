;; ## Salsa20
;;
;; [S20]: http://cr.yp.to/snuffle/spec.pdf
;; Designed to meet the [Salsa20 Spec][S20]
(ns org.azjure.cipher.salsa20
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            [org.azjure.libcrypt :refer (+modw to-hex)]
            [org.azjure.libbyte :refer :all]))

(def ^{:doc "Used to store keystreams for nonces"} salsa20-key-streams
  (atom {}))

;;     {:nonce1 {:counter val :upper val :ks [keystream vector]}}
;;      :nonce2 {:counter val :upper val :ks [keystream vector]}

(def ^{:doc "The maximum keystream length in bytes"} max-stream-length-bytes
  (expt 2 67))

(def ^{:doc "Used during expansion for 32-byte keys."} sigma
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x33]
   [0x32 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(def ^{:doc "Used during expansion for 16-byte keys."}tau
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x31]
   [0x36 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(defn- ^{:doc "quarterround function as defined 
in [Salsa20 Spec][S20]"} quarterround
  [[y0 y1 y2 y3]]
  (let [z1 (bit-xor y1 (<<< (+modw y0 y3) 7))
        z2 (bit-xor y2 (<<< (+modw z1 y0) 9))
        z3 (bit-xor y3 (<<< (+modw z2 z1) 13))
        z0 (bit-xor y0 (<<< (+modw z3 z2) 18))]
    [z0 z1 z2 z3]))

(defn- ^{:doc "rowround function as defined 
in [Salsa20 Spec][S20]"} rowround 
  [[y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]]
  (let [[z0 z1 z2 z3] (quarterround [y0 y1 y2 y3])
        [z5 z6 z7 z4] (quarterround [y5 y6 y7 y4])
        [z10 z11 z8 z9] (quarterround [y10 y11 y8 y9])
        [z15 z12 z13 z14] (quarterround [y15 y12 y13 y14])]
    [z0 z1 z2 z3 z4 z5 z6 z7 z8 z9 z10 z11 z12 z13 z14 z15]))
  
(defn- ^{:doc "columnround function as defined 
in [Salsa20 Spec][S20]"} columnround
  [[x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15]]
  (let [[y0 y4 y8 y12] (quarterround [x0 x4 x8 x12])
        [y5 y9 y13 y1] (quarterround [x5 x9 x13 x1])
        [y10 y14 y2 y6] (quarterround [x10 x14 x2 x6])
        [y15 y3 y7 y11] (quarterround [x15 x3 x7 x11])]
    [y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]))

(defn- ^{:doc "quarterround function as defined 
in [Salsa20 Spec][S20]"} doubleround
  [x _]
  (rowround (columnround x)))

(defn- ^{:doc "salsa20 encryption function as defined 
in [Salsa20 Spec][S20]"} salsa20
  [in]
  (let [x (mapv #(bytes-word % true) (partition 4 in))]
    (->> (range 10)
         (reduce doubleround x)
         (mapv +modw x)
         (mapv #(word-bytes % true))
         (reduce into))))

(defn- ^{:doc "Is the given vector 32 bytes long?"} bytes32?
  [key]
  (= 32 (count key)))

(defn- ^{:doc "Increment the counter in the map in the atom
at noncekw."} inccnt!
  [noncekw counter]
  (swap! salsa20-key-streams assoc noncekw
         (assoc (noncekw @salsa20-key-streams) :counter (inc counter))))

(defn- ^{:doc "A Salsa20 key stream round.  Generates 64-bytes
of keystream."} salsa20-round
  [c k0 k1 noncekw nonce]
  (fn [ks round]
    (let [counter (:counter (noncekw @salsa20-key-streams))
          n (into nonce (x->bv counter))
          _ (inccnt! noncekw counter)]
      (->> [(nth c 0) k0 (nth c 1) n (nth c 2) k1 (nth c 3)]
           (reduce into)
           (salsa20)
           (into ks)))))

(defn- ^{:doc "Generate enough key stream to cover the upper
bound of the range."} gen-key-stream
  [{:keys [key nonce kw]} [lower upper]]
  (let [c (if (bytes32? key) sigma tau)
        k0 (subvec key 0 16)
        k1 (if (bytes32? key) (subvec key 16 32) (subvec key 0 16))
        rounds (inc (quot upper 64))
        rounds (if (not= 0 (rem upper 64)) (inc rounds) rounds)]
    (reduce (salsa20-round c k0 k1 kw nonce) [] (range rounds))))

(defn- ^{:doc "Reset the map in the atom at noncekw."} resetnonce!
  [noncekw]
  (swap! salsa20-key-streams assoc noncekw {:counter 0}))

(defn- ^{:doc "Reset the keystream in the map in the atom
at noncekw."} resetks! 
  [noncekw initmap [lower upper :as range]]
  (let [ks (gen-key-stream (conj {:kw noncekw} initmap) range)]
    (swap! salsa20-key-streams assoc noncekw 
           (assoc (noncekw @salsa20-key-streams) :upper upper :ks ks))))

(defn- ^{:doc "Generate a keyword from the nonce."} gen-keyword
  [nonce]
  (-> (->> (partition 4 nonce)
           (mapv (comp to-hex bytes-word))
           (reduce str))
      (clojure.string/replace #"0x" "")
      (keyword)))

;; ### Salsa20
;; Extend the StreamCipher and Cipher protocol thorough the Salsa20 record type
(defrecord Salsa20 []
  Cipher
  (initialize [_ {:keys [nonce upper] :or {upper 1024} :as initmap}]
    (let [kw (gen-keyword nonce)]
      (do
        (resetnonce! kw)
        (resetks! kw initmap [0 upper]))
      initmap))
  (keysizes-bytes [_] [16 32])
  StreamCipher
  (generate-keystream [_ {:keys [nonce] :as initmap} [lower upper :as range]]
    (let [noncekw (gen-keyword nonce)]
      (when (>= (dec upper) (:upper (noncekw @salsa20-key-streams)))
        (resetnonce! noncekw)
        (resetks! noncekw initmap range))
      (subvec (:ks (noncekw @salsa20-key-streams)) lower upper)))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 8))
