;; ## HC-128
;; 
;; [HC128]: http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
;; Designed to meet the [HC-128 Spec][HC128]
(ns org.azjure.cipher.hc128
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            (org.azjure [libcrypt :refer (+modw -mod512 to-hex)]
                        [libbyte :refer :all])))

(defn- f1 [word]
  (bit-xor (>>> word 7) (>>> word 18) (bit-shift-right word 3)))

(defn- f2 [word]
  (bit-xor (>>> word 17) (>>> word 19) (bit-shift-right word 10)))

(defn- g1 [w1 w2 w3]
  (+modw (bit-xor (>>> w1 10) (>>> w3 23)) (>>> w2 8)))

(defn- g2 [w1 w2 w3]
  (+modw (bit-xor (<<< w1 10) (<<< w3 23)) (<<< w2 8)))

(defn- h1 [q word]
  (+modw (nth q (get-byte 1 word))(nth q (+ (get-byte 3 word) 256))))

(defn- h2 [p word]
  (+modw (nth p (get-byte 1 word))(nth p (+ (get-byte 3 word) 256))))

(defn- append-key [ks key i]
  (->> (mod i 4)
       (nth key)
       (conj ks)))

(defn- append-iv [ks iv i]
  (->> (mod (- i 8) 4)
       (nth iv)
       (conj ks)))

(defn- append-new [ks i]
  (->> (+modw
        (f2 (nth ks (- i 2)))
        (nth ks (- i 7))
        (f1 (nth ks (- i 15)))
        (nth ks (- i 16))
        i)
       (conj ks)))

(defn- key-round [key iv]
  (fn [ks i]
    (cond
     (< i 8)  (append-key ks key i)
     (< i 16) (append-iv ks iv i)
     :else    (append-new ks i))))

(defn- expand-key 
  ([{:keys [key iv] :as initmap}]
     {:pre [(contains? initmap :key) (contains? initmap :iv)
            (vector? key) (vector? iv)
            (= 16 (count key)) (= 16 (count iv))]}
     (let [kw (mapv bytes-word (partition 4 key))
           iw (mapv bytes-word (partition 4 iv))]
       (reduce (key-round kw iw) [] (range 1280)))))

(defn- p-round [ek]
  (fn [p round]
    (conj p (nth ek (+ round 256)))))

(defn- gen-p [ek]
  (reduce (p-round ek) [] (range 512)))

(defn- q-round [ek]
  (fn [q round]
    (conj q (nth ek (+ round 768)))))

(defn- gen-q [ek]
  (reduce (q-round ek) [] (range 512)))

(defn- new-p [p j]
  (->> (+modw
        (nth p j)
        (g1 
         (nth p (-mod512 j 3))
         (nth p (-mod512 j 10))
         (nth p (-mod512 j 511))))
       (assoc p j)))

(defn- new-q [q j]
  (->> (+modw
        (nth q j)
        (g2 
         (nth q (-mod512 j 3))
         (nth q (-mod512 j 10))
         (nth q (-mod512 j 511))))
       (assoc q j)))

(defn- sp [p q j]
  (bit-xor (h1 q (nth p (-mod512 j 12))) (nth p j)))

(defn- sq [p q j]
  (bit-xor (h2 p (nth q (-mod512 j 12))) (nth q j)))

(defn- ks-round [[p q _] round]
  (let [j (mod round 512)]
    (cond
     (< (mod round 1024) 512) (let [np (new-p p j)] [np q (sp np q j)])
     :else (let [nq (new-q q j)] [p nq (sq p nq j)]))))

(defn- p-ks-round [{:keys [p q] :as pq} round]
  (assoc pq :p (assoc p round (last (ks-round [p q 0] round)))))

(defn- q-ks-round [{:keys [p q] :as pq} round]
  (assoc pq :q (assoc q round (last (ks-round [p q 0] (+ 512 round))))))

(defn- remap-p [pq]
  (reduce p-ks-round pq (range 512)))

(defn- remap-q [pq]
  (reduce q-ks-round pq (range 512)))

(def hc128-key-streams (atom {}))
(def max-stream-length-bits (expt 2 64))
(def max-stream-length-bytes (expt 2 61))
(def max-stream-length-words (expt 2 59))

(defn- genkeyword [key iv]
  (-> (->> (into key iv)
           (partition 4)
           (mapv bytes-word)
           (mapv to-hex)
           (apply str))
      (clojure.string/replace #"0x" "")
      (keyword)))

(defn- gen-key-stream [p q upper]
  (let [_ (println "Calling gen-keystream with" upper)]
  (->> (range 0 upper)
       (reductions ks-round [p q 0])
       (rest)
       (mapv (comp word-bytes reverse-bytes last))
       (reduce into))))

;; ### HC128
;; Extend the Cipher and StreamCipher protocol thorough the HC128 record type
(defrecord HC128 []
  Cipher
  (initialize [_ {:keys [key iv upper] :or {upper 1024} :as initmap}]
    (let [ek (expand-key initmap)
          uid (genkeyword key iv)
          keymap (assoc (remap-q (remap-p {:p (gen-p ek) :q (gen-q ek)})) :key key :iv iv)]
      (swap! hc128-key-streams assoc uid {:upper upper :ks (gen-key-stream (:p keymap) (:q keymap) upper)})
      keymap))
  (keysizes-bytes [_] [16])
  StreamCipher
  (generate-keystream [_ {:keys [key iv p q]} [lower upper]]
    (let [uid (genkeyword key iv)]
      (if (< upper (inc (:upper (uid @hc128-key-streams))))
        (subvec (:ks (uid @hc128-key-streams)) lower upper)
        (do
          (swap! hc128-key-streams assoc uid {:upper upper :ks (gen-key-stream p q upper)})
          (subvec (:ks (uid @hc128-key-streams)) lower upper)))))
  (keystream-size-bytes [_] max-stream-length-bytes)
  (iv-size-bytes [_] 16))

