;; ## MICKEY 2.0
;;
;; [M2]: http://www.ecrypt.eu.org/stream/p3ciphers/mickey/mickey_p3.pdf
;; Designed to meet the [MICKEY 2.0 Spec][M2]
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

(defn- ^{:doc "Swap the state in the atom at uid with the default state"}
  swapkiv! [uid {:keys [key iv]}]
  (if (contains? @mickey2-key-streams uid)
    (swap! mickey2-key-streams assoc uid
           (assoc (uid @mickey2-key-streams) :upper 0 :ks []))))

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
