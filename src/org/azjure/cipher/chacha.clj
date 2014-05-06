;; ## Chacha20
;;
;; [C20]: http://cr.yp.to/chacha/chacha-20080128.pdf
;; [S20]: http://cr.yp.to/snuffle/spec.pdf
;; Designed to meet the [ChaCha Spec][C20]

(ns org.azjure.cipher.chacha
  (:require [clojure.math.numeric-tower :refer [expt]]
            [org.azjure.cipher.cipher :refer [Cipher]]
            [org.azjure.cipher.streamcipher :refer [StreamCipher]]
            [org.azjure.libbyte :refer :all]
            [org.azjure.libcrypt :refer :all]))

(def ^{:doc "Used to store keystreams for nonces"}
  chacha-key-streams
  (atom {}))

;;     {:nonce1 {:counter val :upper val :ks [keystream vector]}}
;;      :nonce2 {:counter val :upper val :ks [keystream vector]}

(def ^{:doc "The maximum keystream length in bytes"}
  max-stream-length-bytes
  (expt 2 70))

(def ^{:doc "Used during expansion for 32-byte keys."}
  sigma
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x33]
   [0x32 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(def ^{:doc "Used during expansion for 16-byte keys."}
  tau
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x31]
   [0x36 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(defn- quartersubround [[x y z] sft]
  [(+modw x y) (<<< (bit-xor x z) sft)])

(defn- ^{:doc "quarterround function as defined 
in [ChaCha Spec][C20]"}
  quarterround [[a b c d]]
  (let [[a d] (quartersubround [a b d] 16)
        ;_ (println "ABCD0: " (mapv to-hex [a b c d]))
        [c b] (quartersubround [c d b] 12)
        ;_ (println "ABCD1: " (mapv to-hex [a b c d]))
        [a d] (quartersubround [a b d] 8)
        ;_ (println "ABCD2: " (mapv to-hex [a b c d]))
        [c b] (quartersubround [c d b] 7)
        ;_ (println "ABCD3: " (mapv to-hex [a b c d]))
        ]
    [a b c d]))

(defn- ^{:doc "rowround function as defined 
in [Salsa20 Spec][S20]"}
  rowround [[y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]]
  (let [[z0 z1 z2 z3] (quarterround [y0 y1 y2 y3])
        [z5 z6 z7 z4] (quarterround [y5 y6 y7 y4])
        [z10 z11 z8 z9] (quarterround [y10 y11 y8 y9])
        [z15 z12 z13 z14] (quarterround [y15 y12 y13 y14])]
    [z0 z1 z2 z3 z4 z5 z6 z7 z8 z9 z10 z11 z12 z13 z14 z15]))

(defn- ^{:doc "columnround function as defined 
in [Salsa20 Spec][S20]"}
  columnround [[x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15]]
  (let [[y0 y4 y8 y12] (quarterround [x0 x4 x8 x12])
        [y5 y9 y13 y1] (quarterround [x5 x9 x13 x1])
        [y10 y14 y2 y6] (quarterround [x10 x14 x2 x6])
        [y15 y3 y7 y11] (quarterround [x15 x3 x7 x11])]
    [y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]))

(defn- ^{:doc "quarterround function as defined 
in [Salsa20 Spec][S20]"}
  doubleround [x _]
  (rowround (columnround x)))

(defn- ^{:doc "ChaCha encryption function as defined 
in [ChaCha Spec][C20]"}
  chacha [in]
  (let [x (mapv #(bytes-word % true) (partition 4 in))]
    (->> (range 10)
         (reduce doubleround x)
         (mapv +modw x)
         (mapv #(word-bytes % true))
         (reduce into))))

(defn- ^{:doc "Is the given vector 32 bytes long?"}
  bytes32? [bytes]
  (= 32 (count bytes)))

(defn- ^{:doc "Increment the counter in the map in the atom
at uid."}
  swapcnt! [uid counter]
  (swap! chacha-key-streams assoc uid
         (assoc (uid @chacha-key-streams) :counter (inc counter))))

(defn- ^{:doc "A ChaCha key stream round.  Generates 64-bytes
of keystream."}
  chacha-round [c k0 k1 uid nonce]
  (fn [ks round]
    (let [counter (:counter (uid @chacha-key-streams))
          n (into nonce (x->bv counter))
          _ (swapcnt! uid counter)]
      (->> [(nth c 0) k0 (nth c 1) n (nth c 2) k1 (nth c 3)]
           (reduce into)
           (chacha)
           (into ks)))))

(defn- ^{:doc "Generate enough key stream to cover the upper
bound of the range."} gen-key-stream
  [{:keys [key nonce uid lower upper]}]
  (let [c (if (bytes32? key) sigma tau)
        k0 (subvec key 0 16)
        k1 (if (bytes32? key) (subvec key 16 32) (subvec key 0 16))
        rounds (inc (quot upper 64))
        rounds (if (not= 0 (rem upper 64)) (inc rounds) rounds)]
    (reduce (chacha-round c k0 k1 uid nonce) [] (range rounds))))

(defn- ^{:doc "Reset the map in the atom at uid to defaults."}
  swapuid! [{:keys [uid]}]
  (swap! chacha-key-streams assoc uid {:counter 0}))

(defn- ^{:doc "Reset the keystream in the map in the atom
at uid."}
  swapks! [{:keys [uid upper] :as initmap}]
  (let [ks (gen-key-stream (assoc initmap :lower 0))]
    (swap! chacha-key-streams assoc uid
           (assoc (uid @chacha-key-streams) :upper upper :ks ks))))

;; ### Chacha
;; Extend the StreamCipher and Cipher protocol thorough the Chacha record type
(defrecord Chacha []
  Cipher
  (initialize [_ {:keys [key nonce upper] :or {upper 1024} :as initmap}]
    (let [uid (bytes->keyword (into key nonce))
          initmap (assoc initmap :upper upper :uid uid)]
      (do
        (swapuid! initmap)
        (swapks! initmap))
      initmap))
  (keysizes-bytes [_] [16 32])
  StreamCipher
  (generate-keystream [_ {:keys [uid lower upper] :as initmap} _]
    (when (>= (dec upper) (:upper (uid @chacha-key-streams)))
      (swapuid! initmap)
      (swapks! initmap))
    (subvec (:ks (uid @chacha-key-streams)) lower upper))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 8))
