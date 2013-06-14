;; ## HC-256
;;
;; [HC256]: http://www3.ntu.edu.sg/home/wuhj/research/hc/hc256_fse.pdf
;; Designed to meet the [HC-256 Spec][HC256]
(ns org.azjure.cipher.hc256
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            (org.azjure [libcrypt :refer :all]
                        [libbyte :refer :all])))

(def ^{:doc "Used to store upper bounds and current keystreams
for initialized key/iv pairs"}
  hc256-key-streams (atom {}))

;;     {:keyiv1 {:upper val :ks [keystream vector]}
;;      :keyiv2 {:upper val :ks [keystream vector]}

(def ^{:doc "The maximum keystream length in bytes"}
  max-stream-length-bytes (expt 2 125))

;; ### HC-256 Specification Functions

(defn- ^{:doc "f1 function as defined in [HC-256 Spec][HC256].
Takes a 32-bit word value and evaluates to a 32-bit word."}
  f1 [x]
  (bit-xor (>>> x 7) (>>> x 18) (bit-shift-right x 3)))

(defn- ^{:doc "f2 function as defined in [HC-256 Spec][HC256].
Takes a 32-bit word value and evaluates to a 32-bit word."}
  f2 [x]
  (bit-xor (>>> x 17) (>>> x 19) (bit-shift-right x 10)))

(defn- ^{:doc "g1 function as defined in [HC-256 Spec][HC256].
Takes three 32-bit word values and evaluates to a 32-bit word."}
  g1 [x y q]
  (+modw (bit-xor (>>> x 10) (>>> y 23)) (nth q (mod (bit-xor x y) 1024))))

(defn- ^{:doc "g2 function as defined in [HC-256 Spec][HC256].
Takes three 32-bit word values and evaluates to a 32-bit word."}
  g2 [x y p]
  (+modw (bit-xor (>>> x 10) (>>> y 23)) (nth p (mod (bit-xor x y) 1024))))

(defn- ^{:doc "h1 function as defined in [HC-256 Spec][HC256].
Uses the q sbox and a 32-bit word value and evaluates to a 32-bit word."}
  h1 [q word]
  (+modw (nth q (get-byte 1 word))
         (nth q (+ (get-byte 2 word) 256))
         (nth q (+ (get-byte 3 word) 512))
         (nth q (+ (get-byte 4 word) 768))))

(defn- ^{:doc "h2 function as defined in [HC-256 Spec][HC256].
Uses the p sbox and a 32-bit word value and evaluates to a 32-bit word."}
  h2 [p word]
  (+modw (nth p (get-byte 1 word))
         (nth p (+ (get-byte 2 word) 256))
         (nth p (+ (get-byte 3 word) 512))
         (nth p (+ (get-byte 4 word) 768))))

(defn- ^{:doc "Add the key to the subkeys vector."}
  append-key [ks key i]
  (->> (nth key i)
       (conj ks)))

(defn- ^{:doc "Add the IV to the subkeys vector."}
  append-iv [ks iv i]
  (->> (mod i 8) 
       (nth iv)
       (conj ks)))

(defn- ^{:doc "Add the newly calculated word values to the 
subkeys vector."}
  append-new [ks i]
  (->> (+modw
        (f2 (nth ks (- i 2)))
        (nth ks (- i 7))
        (f1 (nth ks (- i 15)))
        (nth ks (- i 16))
        i)
       (conj ks)))

(defn- ^{:doc "Add one word to the key schedule vector
based on the round number"}
  key-round [key iv]
  (fn [ks round]
    (cond
      (< round 8)  (append-key ks key round)
      (< round 16) (append-iv ks iv round)
      :else        (append-new ks round))))

(defn- ^{:doc "Expand the key into a vector of 2560 32-bit words."}
  expand-key 
  ([{:keys [key iv] :as initmap}]
     {:pre [(contains? initmap :key) (contains? initmap :iv)
            (vector? key) (vector? iv)
            (= 32 (count key)) (= 32 (count iv))]}
     (let [kw (mapv bytes-word (partition 4 key))
           iw (mapv bytes-word (partition 4 iv))]
       (reduce (key-round kw iw) [] (range 2560)))))

(defn- ^{:doc "conj a value from the key schedule onto the p sbox."}
  p-round [ek]
  (fn [p round]
    (conj p (nth ek (+ round 512)))))

(defn- ^{:doc "Generate the initial p-sbox."}
  gen-p [ek]
  (reduce (p-round ek) [] (range 1024)))

(defn- ^{:doc "conj a value from the key schedule onto the q sbox."}
  q-round [ek]
  (fn [q round]
    (conj q (nth ek (+ round 1536)))))

(defn- ^{:doc "Generate the initial q-sbox."}
  gen-q [ek]
  (reduce (q-round ek) [] (range 1024)))

(defn- ^{:doc "Calculate and place a new value in the p sbox at index j"}
  new-p [p q j]
  (->> (+modw
        (nth p j)
        (nth p (-mod1024 j 10))
        (g1 
         (nth p (-mod1024 j 3))
         (nth p (-mod1024 j 1023))
         q))
       (assoc p j)))

(defn- ^{:doc "Calculate and place a new value in the q sbox at index j"}
  new-q [p q j]
  (->> (+modw
        (nth q j)
        (nth q (-mod1024 j 10))
        (g2 
         (nth q (-mod1024 j 3))
         (nth q (-mod1024 j 1023))
         p))
       (assoc q j)))

(defn- ^{:doc "Calculate an output word during the lower 1024."}
  sp [p q j]
  (bit-xor (h1 q (nth p (-mod1024 j 12))) (nth p j)))

(defn- ^{:doc "Calculate an output word during the upper 1024."}
  sq [p q j]
  (bit-xor (h2 p (nth q (-mod1024 j 12))) (nth q j)))

(defn- ^{:doc "The hc256 cipher function as defined
in [HC-256 Spec][HC256]."}
  hc256 [ke]
  (fn [[p q out] round]
    (let [j (mod round 1024)]
      (cond
       (< (mod round 2048) 1024) (let [np (new-p p q j)] [np q (if ke out (conj out (sp np q j)))])
       :else (let [nq (new-q p q j)] [p nq (if ke out (conj out (sq p nq j)))])))))

(defn- ^{:doc "Recalculate the sboxes during key expansion."}
  gen-sboxes [p q]
  (reduce (hc256 true) [p q []] (range 4096)))

(defn- ^{:doc "Reset the map in the atom at uid."}
  resetkiv! [uid initmap]
  (if (contains? @hc256-key-streams uid)
    (swap! hc256-key-streams assoc uid
           (assoc (uid @hc256-key-streams) :upper 0 :ks []))
    (let [ek (expand-key initmap)
          [p q _] (gen-sboxes (gen-p ek) (gen-q ek))]
      (swap! hc256-key-streams assoc uid {:p p :q q}))))

(defn- ^{:doc "Reset the keystream in the map in the atom
at uid."}
  resetks! [uid upper]
  (let [p (:p (uid @hc256-key-streams))
        q (:q (uid @hc256-key-streams))
        ks (->> (range upper)
                (reduce (hc256 false) [p q []])
                (last)
                (mapv word-bytes)
                (reduce into))]
    (swap! hc256-key-streams assoc uid
           (assoc (uid @hc256-key-streams) :upper upper :ks ks))))

;; ### HC256
;; Extend the Cipher and StreamCipher protocol thorough the HC256 record type
(defrecord HC256 []
  Cipher
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [uid (bytes->keyword (into key iv))]
      (do
        (resetkiv! uid initmap)
        (resetks! uid upper))
      initmap))
  (keysizes-bytes [_] [32])
  StreamCipher
  (generate-keystream [_ {:keys [key iv lower upper] :as initmap} _]
    (let [uid (bytes->keyword (into key iv))]
      (when (>= (dec upper) (:upper (uid @hc256-key-streams)))
        (resetkiv! uid initmap)
        (resetks! uid upper))
      (subvec (:ks (uid @hc256-key-streams)) lower upper)))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 32))
