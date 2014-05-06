;; ## Grain-128
;;
;; [GRAIN]: http://www.ecrypt.eu.org/stream/p3ciphers/grain/Grain128_p3.pdf
;; Designed to meet the [Grain-128 Spec][GRAIN]

(ns org.azjure.cipher.grain128
  (:require [clojure.math.numeric-tower :refer [expt]]
            [org.azjure.cipher.cipher :refer [Cipher]]
            [org.azjure.cipher.streamcipher :refer [StreamCipher]]
            [org.azjure.libbyte :refer :all]
            [org.azjure.libcrypt :refer :all]))

(def ^{:private true :doc "Used to store upper bounds and current keystreams
for initialized key/iv pairs"}
  grain128-key-streams (atom {}))

;;     {:keyiv1 {:upper val :ks [keystream vector]}
;;      :keyiv2 {:upper val :ks [keystream vector]}

(def ^{:private true :doc "The maximum keystream length in bytes"}
  max-stream-length-bytes (expt 2 61))

(defn- ^{:doc "Get the values out of the given shift register at the given
indices"}
  nthsr [sr indices]
  (mapv (partial nth sr) indices))

(defn- ^{:doc "The bent function as defined in [Grain-128 Spec][GRAIN]"}
  bent-fn [nfsr lfsr]
  [(bit-and (nth nfsr 12) (nth lfsr 8))
   (bit-and (nth lfsr 13) (nth lfsr 20))
   (bit-and (nth nfsr 95) (nth lfsr 42))
   (bit-and (nth lfsr 60) (nth lfsr 79))
   (bit-and (nth nfsr 12) (nth nfsr 95) (nth lfsr 95))])

(defn- ^{:doc "Generate one output bit and update the shift registers"}
  grain-round [[nfsr lfsr _] _]
  (let [outbit (->> (bent-fn nfsr lfsr)
                    (into (nthsr lfsr [93]))
                    (into (nthsr nfsr [2 15 36 45 64 73 89]))
                    (reduce bit-xor))
        nbit (->> (nthsr nfsr [67 13 18 59 48 65 84])
                  (mapv bit-and (nthsr nfsr [3 11 17 27 40 61 68]))
                  (into (nthsr nfsr [0 26 56 91 96]))
                  (into (nthsr lfsr [0]))
                  (reduce bit-xor))
        lbit (reduce bit-xor (nthsr lfsr [0 7 38 70 81 96]))]
    [(conj (subvec nfsr 1) nbit)
     (conj (subvec lfsr 1) lbit)
     outbit]))

(defn- ^{:doc "Add an output bit to the stream"}
  keystream-round [[nfsr lfsr stream] round]
  (let [[nfsr lfsr outbit] (grain-round [nfsr lfsr 0] round)]
    [nfsr lfsr (conj stream outbit)]))

(defn- ^{:doc "Generate the next register bit during keystream initialization"}
  keyinit-round [[nfsr lfsr :as srs] round]
  (let [[nfsr lfsr outbit] (grain-round srs round)]
    [(assoc nfsr 127 (bit-xor (nth nfsr 127) outbit))
     (assoc lfsr 127 (bit-xor (nth lfsr 127) outbit))]))

(defn- ^{:doc "Expand the key/iv into bits"}
  expand-key [key iv]
  (let [paddediv (into iv (vec (take (- 16 (count iv)) (cycle [0xFF]))))
        keybits (reduce into (mapv (comp vec reverse byte->bits) key))
        ivbits (reduce into (mapv (comp vec reverse byte->bits) paddediv))]
  [keybits ivbits]))

(defn- ^{:doc "Swap the state in the atom at uid with the default state"}
  swapkiv! [uid {:keys [key iv]}]
  (if (contains? @grain128-key-streams uid)
    (swap! grain128-key-streams assoc uid
           (assoc (uid @grain128-key-streams) :upper 0 :ks []))
    (let [[nfsr lfsr] (reduce keyinit-round (expand-key key iv) (range 256))]
      (swap! grain128-key-streams assoc uid {:nfsr nfsr :lfsr lfsr}))))

(defn- ^{:doc "Swap any existing keystream at uid with a newly generated one"}
  swapks! [uid upper]
  (let [nfsr (:nfsr (uid @grain128-key-streams))
        lfsr (:lfsr (uid @grain128-key-streams))
        ks (->> (range (* 8 upper)) ; 8 bits per byte
                (reduce keystream-round [nfsr lfsr []])
                (peek)
                (partition 8)
                (mapv bits->byte))]
    (swap! grain128-key-streams assoc uid
           (assoc (uid @grain128-key-streams) :upper upper :ks ks))))

;; ### Grain128
;; Extend the Cipher and StreamCipher protocol thorough the Grain128 record type
(defrecord Grain128 []
  Cipher
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [uid (bytes->keyword (into key iv))]
      (do
        (swapkiv! uid initmap)
        (swapks! uid upper))
      initmap))
  (keysizes-bytes [_] [16])
  StreamCipher
  (generate-keystream [_ {:keys [key iv lower upper] :as initmap} _]
    (let [uid (bytes->keyword (into key iv))]
      (when (>= (dec upper) (:upper (uid @grain128-key-streams)))
        (swapkiv! uid initmap)
        (swapks! uid upper))
      (subvec (:ks (uid @grain128-key-streams)) lower upper)))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 12))
