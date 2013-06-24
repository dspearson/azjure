;; ## MICKEY 2.0
;;
;; [M2]: http://www.ecrypt.eu.org/stream/p3ciphers/mickey/mickey_p3.pdf
;; Designed to meet the [MICKEY2.0 Spec][M2]
(ns org.azjure.cipher.mickey2
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            (org.azjure [libcrypt :refer :all]
                        [libbyte :refer :all])))

(def ^{:private true :doc "Used to store upper bounds and current keystreams
for initialized key/iv pairs"}
  mickey2-key-streams (atom {}))

;;     {:keyiv1 {:upper val :ks [keystream vector]}
;;      :keyiv2 {:upper val :ks [keystream vector]}

(def ^{:private true :doc "The maximum keystream length in bytes"}
  max-stream-length-bytes (expt 2 37))

(def ^{:private true :doc "rtaps as defined in the [MICKEY2.0 Spec][M2]"}
  rtaps #{0 1 3 4 5 6 9 12 13 16 19 20 21 22 25 28 37 38 41 42 45 46 50 52
          54 56 58 60 61 63 64 65 66 67 71 72 79 80 81 82 87 88 89 90 91 92
          94 95 96 97})

(defn- ^{:doc "xor with the feedback bit if the index is in rtaps"}
  rtapper [feedback-bit]
  (fn [r idx]
    (if (contains? rtaps idx)
      (assoc r idx (bit-xor feedback-bit (nth r idx)))
      r)))

(defn- ^{:doc "xor the original value with the new value"}
  rxor [r] 
  (fn [rprime idx]
    (assoc rprime idx (bit-xor (nth r idx) (nth rprime idx)))))

(defn- ^{:doc "Clock the r register"}
  clock-r [r input-bit control-bit]
  (let [feedback-bit (bit-xor (nth r 99) input-bit)
        rprime (vec (conj (drop-last r) 0))
        rprime (reduce (rtapper feedback-bit) rprime (range 100))]
    (if (= 1 control-bit)
      (reduce (rxor r) rprime (range 100))
      rprime)))

(defn- ^{:doc "Swap the state in the atom at uid with the default state"}
  swapkiv! [uid {:keys [key iv]}]
  (if (contains? @mickey2-key-streams uid)
    (swap! mickey2-key-streams assoc uid
           (assoc (uid @mickey2-key-streams) :upper 0 :ks []))
    (clock-r (vec (take 100 (cycle [1]))) 0 1)
    ))

(defn- ^{:doc "Swap any existing keystream at uid with a newly generated one"}
  swapks! [uid upper]
  (let [ks nil]
    (swap! mickey2-key-streams assoc uid
           (assoc (uid @mickey2-key-streams) :upper upper :ks ks))))

;; ### MICKEY2.0
;; Extend the Cipher and StreamCipher protocol thorough the Mickey2 record type
(defrecord Mickey2 []
  Cipher
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [uid (bytes->keyword (into key iv))]
      (do
        (swapkiv! uid initmap)
        (swapks! uid upper))
      initmap))
  (keysizes-bytes [_] [10])
  StreamCipher
  (generate-keystream [_ {:keys [key iv lower upper] :as initmap} _]
    (let [uid (bytes->keyword (into key iv))]
      (when (>= (dec upper) (:upper (uid @mickey2-key-streams)))
        (swapkiv! uid initmap)
        (swapks! uid upper))
      (subvec (:ks (uid @mickey2-key-streams)) lower upper)))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 10))
