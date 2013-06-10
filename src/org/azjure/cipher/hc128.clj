;; ## HC-128
;; 
;; [HC128]: http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
;; Designed to meet the [HC-128 Spec][HC128]
(ns org.azjure.cipher.hc128
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            (org.azjure [libcrypt :refer (to-hex +modw -mod512)]
                        [libbyte :refer :all])))

(def ^{:doc "Used to store upper bounds and current keystreams
for initialized key/iv pairs"} hc128-key-streams
  (atom {}))

;;     {:keyiv1 {:upper val :ks [keystream vector]}
;;      :keyiv2 {:upper val :ks [keystream vector]}

(def ^{:doc "The maximum keystream length in bytes"} max-stream-length-bytes
  (expt 2 61))

;; ### HC-128 Specification Functions

(defn- ^{:doc "f1 function as defined in [HC-128 Spec][HC128].
Takes a 32-bit word value and evaluates to a 32-bit word."} f1 
  [word]
  (bit-xor (>>> word 7) (>>> word 18) (bit-shift-right word 3)))

(defn- ^{:doc "f2 function as defined in [HC-128 Spec][HC128].
Takes a 32-bit word value and evaluates to a 32-bit word."} f2 
  [word]
  (bit-xor (>>> word 17) (>>> word 19) (bit-shift-right word 10)))

(defn- ^{:doc "g1 function as defined in [HC-128 Spec][HC128].
Takes three 32-bit word values and evaluates to a 32-bit word."} g1 
  [w1 w2 w3]
  (+modw (bit-xor (>>> w1 10) (>>> w3 23)) (>>> w2 8)))

(defn- ^{:doc "g2 function as defined in [HC-128 Spec][HC128].
Takes three 32-bit word values and evaluates to a 32-bit word."} g2
  [w1 w2 w3]
  (+modw (bit-xor (<<< w1 10) (<<< w3 23)) (<<< w2 8)))

(defn- ^{:doc "h1 function as defined in [HC-128 Spec][HC128].
Uses the q sbox and a 32-bit word value and evaluates to a 32-bit word."} h1
  [q word]
  (+modw (nth q (get-byte 1 word))(nth q (+ (get-byte 3 word) 256))))

(defn- ^{:doc "h2 function as defined in [HC-128 Spec][HC128].
Uses the p sbox and a 32-bit word value and evaluates to a 32-bit word."} h2
  [p word]
  (+modw (nth p (get-byte 1 word))(nth p (+ (get-byte 3 word) 256))))

(defn- ^{:doc "Add the key to the subkeys vector."} append-key 
  [ks key i]
  (->> (mod i 4)
       (nth key)
       (conj ks)))

(defn- ^{:doc "Add the IV to the subkeys vector."} append-iv 
  [ks iv i]
  (->> (mod (- i 8) 4)
       (nth iv)
       (conj ks)))

(defn- ^{:doc "Add the newly calculated word values to the 
subkeys vector."} append-new
  [ks i]
  (->> (+modw
        (f2 (nth ks (- i 2)))
        (nth ks (- i 7))
        (f1 (nth ks (- i 15)))
        (nth ks (- i 16))
        i)
       (conj ks)))

(defn- ^{:doc "Add one word to the key schedule vector
based on the round number"} key-round 
  [key iv]
  (fn [ks round]
    (cond
      (< round 8)  (append-key ks key round)
      (< round 16) (append-iv ks iv round)
      :else        (append-new ks round))))

(defn- ^{:doc "Expand the key into a vector of 1280 32-bit words."} expand-key 
  ([{:keys [key iv] :as initmap}]
     {:pre [(contains? initmap :key) (contains? initmap :iv)
            (vector? key) (vector? iv)
            (= 16 (count key)) (= 16 (count iv))]}
     (let [kw (mapv bytes-word (partition 4 key))
           iw (mapv bytes-word (partition 4 iv))]
       (reduce (key-round kw iw) [] (range 1280)))))

(defn- ^{:doc "conj a value from the key schedule onto the p sbox."} p-round
  [ek]
  (fn [p round]
    (conj p (nth ek (+ round 256)))))

(defn- ^{:doc "Generate the initial p-sbox."} gen-p
  [ek]
  (reduce (p-round ek) [] (range 512)))

(defn- ^{:doc "conj a value from the key schedule onto the q sbox."} q-round
  [ek]
  (fn [q round]
    (conj q (nth ek (+ round 768)))))

(defn- ^{:doc "Generate the initial q-sbox."} gen-q
  [ek]
  (reduce (q-round ek) [] (range 512)))

(defn- ^{:doc "Calculate and place a new value in the p sbox at index j"} new-p
  [p j]
  (->> (+modw
        (nth p j)
        (g1 
         (nth p (-mod512 j 3))
         (nth p (-mod512 j 10))
         (nth p (-mod512 j 511))))
       (assoc p j)))

(defn- ^{:doc "Calculate and place a new value in the q sbox at index j"} new-q
  [q j]
  (->> (+modw
        (nth q j)
        (g2 
         (nth q (-mod512 j 3))
         (nth q (-mod512 j 10))
         (nth q (-mod512 j 511))))
       (assoc q j)))

(defn- ^{:doc "Calculate an output word during the lower 512."} sp
  [p q j]
  (bit-xor (h1 q (nth p (-mod512 j 12))) (nth p j)))

(defn- ^{:doc "Calculate an output word during the upper 512."} sq
  [p q j]
  (bit-xor (h2 p (nth q (-mod512 j 12))) (nth q j)))

(defn- ^{:doc "The hc128 cipher function as defined
in [HC-128 Spec][HC128]."} hc128
  [[p q _] round]
  (let [j (mod round 512)]
    (cond
     (< (mod round 1024) 512) (let [np (new-p p j)] [np q (sp np q j)])
     :else (let [nq (new-q q j)] [p nq (sq p nq j)]))))

(defn- ^{:doc "Recalculate a p word given a round."} p-ks-round
  [{:keys [p q] :as pq} round]
  (assoc pq :p (assoc p round (last (hc128 [p q 0] round)))))

(defn- ^{:doc "Recalculate a q word given a round."} q-ks-round
  [{:keys [p q] :as pq} round]
  (assoc pq :q (assoc q round (last (hc128 [p q 0] (+ 512 round))))))

(defn- ^{:doc "Recalculate the p sbox during key expansion."} remap-p
  [pq]
  (reduce p-ks-round pq (range 512)))

(defn- ^{:doc "Recalculate the q sbox during key expansion."} remap-q
  [pq]
  (reduce q-ks-round pq (range 512)))

(defn- ^{:doc "Generate a keyword based on the Key/IV pair."} genkeyword
  [key iv]
  (-> (->> (into key iv)
           (partition 4)
           (mapv bytes-word)
           (mapv to-hex)
           (apply str))
      (clojure.string/replace #"0x" "")
      (keyword)))

(defn- ^{:doc "Generate a key stream for length bytes."} gen-key-stream
  [p q length]
  (->> (range 0 length)
       (reductions hc128 [p q 0])
       (rest)
       (mapv (comp word-bytes reverse-bytes last))
       (reduce into)))

(defn- ^{:doc "Reset the map in the atom at kivkw."} resetkiv!
  [kivkw]
  (swap! hc128-key-streams assoc kivkw {}))

(defn- ^{:doc "Reset the keystream in the map in the atom
at kivkw."} resetks!
  [kivkw {:keys [p q]} [lower upper :as range]]
  (let [ks (gen-key-stream p q upper)]
    (swap! hc128-key-streams assoc kivkw
           (assoc (kivkw @hc128-key-streams) :upper upper :ks ks))))

;; ### HC128
;; Extend the Cipher and StreamCipher protocol thorough the HC128 record type
(defrecord HC128 []
  Cipher
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [kivkw (genkeyword key iv)
          ek (expand-key initmap)
          keymap (-> (remap-p {:p (gen-p ek) :q (gen-q ek)})
                     (remap-q)
                     (assoc :key key :iv iv))]
      (do
        (resetkiv! kivkw)
        (resetks! kivkw keymap [0 upper]))
      keymap))
  (keysizes-bytes [_] [16])
  StreamCipher
  (generate-keystream [_ {:keys [key iv] :as initmap} [lower upper :as range]]
    (let [kivkw (genkeyword key iv)]
      (when (>= (dec upper) (:upper (kivkw @hc128-key-streams)))
        (resetkiv! kivkw)
        (resetks! kivkw initmap range))
      (subvec (:ks (kivkw @hc128-key-streams)) lower upper)))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 16))
