;; ## MICKEY 2.0
;;
;; [M2]: http://www.ecrypt.eu.org/stream/p3ciphers/mickey/mickey_p3.pdf
;; Designed to meet the [MICKEY2.0 Spec][M2]

(ns org.azjure.cipher.mickey2
  (:require [clojure.math.numeric-tower :refer [expt]]
            [org.azjure.cipher.cipher :refer [Cipher]]
            [org.azjure.cipher.streamcipher :refer [StreamCipher]]
            [org.azjure.libbyte :refer :all]
            [org.azjure.libcrypt :refer :all]))

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

(def ^{:private true :doc "comp0 as defined in the [MICKEY2.0 Spec][M2]"}
  comp0 [2 0 0 0 1 1 0 0 0 1 0 1 1 1 1 0 1 0 0 1 0 1 0 1 0 
         1 0 1 0 1 1 0 1 0 0 1 0 0 0 0 0 0 0 1 0 1 0 1 0 1
         0 0 0 0 1 0 1 0 0 1 1 1 1 0 0 1 0 1 0 1 1 1 1 1 1
         1 1 1 0 1 0 1 1 1 1 1 1 0 1 0 1 0 0 0 0 0 0 1 1 2])

(def ^{:private true :doc "comp1 as defined in the [MICKEY2.0 Spec][M2]"}
  comp1 [2 1 0 1 1 0 0 1 0 1 1 1 1 0 0 1 0 1 0 0 0 1 1 0 1
         0 1 1 1 0 1 1 1 1 0 0 0 1 1 0 1 0 1 1 1 0 0 0 0 1
         0 0 0 1 0 1 1 1 0 0 0 1 1 1 1 1 1 0 1 0 1 1 1 0 1
         1 1 1 0 0 0 1 0 0 0 0 1 1 1 0 0 0 1 0 0 1 1 0 0 2])

(def ^{:private true :doc "fb0 as defined in the [MICKEY2.0 Spec][M2]"}
  fb0 [1 1 1 1 0 1 0 1 1 1 1 1 1 1 1 0 0 1 0 1 1 1 1 1 1
       1 1 1 1 0 0 1 1 0 0 0 0 0 0 1 1 1 0 0 1 0 0 1 0 1
       0 1 0 0 1 0 1 1 1 1 0 1 0 1 0 1 0 0 0 0 0 0 0 0 0
       1 1 0 1 0 0 0 1 1 0 1 1 1 0 0 1 1 1 0 0 1 1 0 0 0])

(def ^{:private true :doc "fb1 as defined in the [MICKEY2.0 Spec][M2]"}
  fb1 [1 1 1 0 1 1 1 0 0 0 0 1 1 1 0 1 0 0 1 1 0 0 0 1 0
       0 1 1 0 0 1 0 1 1 0 0 0 1 1 0 0 0 0 0 1 1 0 1 1 0
       0 0 1 0 0 0 1 0 0 1 0 0 1 0 1 1 0 1 0 1 0 0 1 0 1
       0 0 0 1 1 1 1 0 1 1 1 1 1 0 0 0 0 0 0 1 0 0 0 0 1])

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

(defn- ^{:doc "Calculate a new sint value at idx"}
  comp-s [s]
  (fn [sint idx]
    (let [si (nth s idx)
          si- (nth s (dec idx))
          si+ (nth s (inc idx))
          sicaret (->> (bit-xor (nth comp1 idx) si+)
                       (bit-and (bit-xor (nth comp0 idx) si))
                       (bit-xor si-))]
      (assoc sint idx sicaret))))

(defn- ^{:doc "Calculate a new sprime value at idx"}
  fb-s [s fb fbb]
  (fn [sprime idx]
    (assoc sprime idx (bit-xor (nth s idx) (bit-and (nth fb idx) fbb)))))

(defn- ^{:doc "Clock the s register"}
  clock-s [s input-bit control-bit]
  (let [feedback-bit (bit-xor (nth s 99) input-bit)
        scaret (assoc (assoc (reduce (comp-s s) s (range 1 99)) 0 0) 99 (nth s 98))]
    (if (= 0 control-bit)
      (reduce (fb-s scaret fb0 feedback-bit) scaret (range 100))
      (reduce (fb-s scaret fb1 feedback-bit) scaret (range 100)))))

(defn- ^{:doc "Clock the key generator"}
  clock-kg [mixing]
  (fn [[r s] input-bit]
    (let [cbr (bit-xor (nth s 34) (nth r 67))
          cbs (bit-xor (nth s 67) (nth r 33))
          ibr (if mixing (bit-xor input-bit (nth s 50)) input-bit)
          ibs input-bit]
      [(clock-r r ibr cbr)
       (clock-s s ibs cbs)])))

(defn- ^{:doc "Generate a single keystream bit and conj it on to the output
vector"}
  key-stream-round [[r s out] _]
  (let [[nr ns] ((clock-kg false) [r s] 0)]
    [nr ns (conj out (bit-xor (nth r 0)(nth s 0)))]))

(defn- ^{:doc "Swap the state in the atom at uid with the default state"}
  swapkiv! [uid {:keys [key iv]}]
  (if (contains? @mickey2-key-streams uid)
    (swap! mickey2-key-streams assoc uid
           (assoc (uid @mickey2-key-streams) :upper 0 :ks []))
    (let [init (vec (take 100 (cycle [0])))
          ivbits (reduce into (mapv byte->bits iv))
          keybits (reduce into (mapv byte->bits key))
          clkfn (clock-kg true)
          ivloaded (reduce clkfn [init init] ivbits) ; Load IV
          keyloaded (reduce clkfn ivloaded keybits) ; Load key 
          [r s] (reduce clkfn keyloaded init) ; Preclock
          ]
      (swap! mickey2-key-streams assoc uid {:r r :s s}))))

(defn- ^{:doc "Swap any existing keystream at uid with a newly generated one"}
  swapks! [uid upper]
  (let [r (:r (uid @mickey2-key-streams))
        s (:s (uid @mickey2-key-streams))
        ks (->> (range (* 8 upper)) ; 8 bits per byte 
                (reduce key-stream-round [r s []])
                (peek)
                (partition 8)
                (mapv (comp bits->byte reverse)))]
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
