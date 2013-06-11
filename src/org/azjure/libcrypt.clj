;; ## libcrypt
;; Library functions
(ns ^{:author "Jason Ozias"}
  org.azjure.libcrypt
  (:require [org.azjure.cipher.blockcipher :as bc]))

;; ### to-hex
;; Print a value as hex prefixed by 0x.
;;
;; Useful for testing
(defn to-hex 
  ([val len] (format (str "0x%0" len "X") val))
  ([val] (to-hex val 8)))

(defmacro maybe
  "Assuming that the body of code returns X, this macro returns [X nil] in the case of no error
  and [nil E] in event of an exception object E."
  [& body]
  `(try [(do ~@body) nil]
     (catch Error e#
       [nil e#])))

;; ### bytes-per-block
(defn- bytes-per-block [cipher]
  (/ (bc/blocksize cipher) 8))

;; ### mbpb
;; Memoization of bytes-per-block
(def mbpb (memoize bytes-per-block))

;; ### Modulus math

(defn- ^{:doc "x + y mod z"} +modz [z]
  (fn [x y] (-> (+ x y)
                (mod z))))

(defn- ^{:doc "x - y mod z"} -modz [z]
  (fn [x y] (-> (- x y)
                (mod z))))

(defn ^{:doc "x + y mod 8"} +mod8
  ([] 0)
  ([x] x)
  ([x y] ((+modz 8) x y))
  ([x y & more]
     (reduce +mod8 (+mod8 x y) more)))

(defn ^{:doc "x + y mod 32"} +mod32
  ([] 0)
  ([x] x)
  ([x y] ((+modz 32) x y))
  ([x y & more]
     (reduce +mod32 (+mod32 x y) more)))

(defn ^{:doc "x + y mod mod 2^32"} +modw
  ([] 0)
  ([x] x)
  ([x y] ((+modz 0x100000000) x y))
  ([x y & more]
     (reduce +modw (+modw x y) more)))

(defn ^{:doc "x - y mod 512"} -mod512
  ([] 0)
  ([x] x)
  ([x y] ((-modz 512) x y))
  ([x y & more]
     (reduce -mod512 (-mod512 x y) more)))

(defn ^{:doc "x - y mod 2^32"} -modw
  ([] 0)
  ([x] x)
  ([x y] ((-modz 0x100000000) x y))
  ([x y & more]
     (reduce -modw (-modw x y) more)))
