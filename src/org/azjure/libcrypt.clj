;; ## libcrypt
;; Library functions
(ns ^{:author "Jason Ozias"}
  org.azjure.libcrypt
  (:require [org.azjure.libbyte :refer (bytes-word)]
            [org.azjure.cipher.blockcipher :as bc]))

;; ### to-hex
;; Print a value as hex prefixed by 0x.
;;
;; Useful for testing
(defn to-hex 
  ([val len] (format (str "0x%0" len "X") val))
  ([val] (to-hex val 8)))

(defn string->hexstrvec [string]
  (mapv (partial apply str) (mapv #(into % '(\x \0)) (partition 2 string))))

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

(defn ^{:doc "x op y mod z"} modz [op z]
  (fn this
    ([] 0)
    ([x] x)
    ([x y] (-> (op x y)
               (mod z)))
    ([x y & more]
       (apply this (this x y) more))))

(def ^{:doc "x + y mod 8"}    +mod8     (modz + 8))
(def ^{:doc "x + y mod 32"}   +mod32    (modz + 32))
(def ^{:doc "x + y mod 2^32"} +modw     (modz + 0x100000000))
(def ^{:doc "x - y mod 2^64"} +moddw    (modz + 0x10000000000000000))
(def ^{:doc "x - y mod 512"}  -mod512   (modz - 512))
(def ^{:doc "x - y mod 1024"} -mod1024  (modz - 1024))
(def ^{:doc "x - y mod 2^32"} -modw     (modz - 0x100000000))
(def ^{:doc "x - y mod 2^64"} -moddw    (modz - 0x10000000000000000))

(defn ^{:doc "Generate a keyword from the given vector of bytes."}
  bytes->keyword [bytes]
  (-> (->> (partition 4 bytes)
           (mapv (comp to-hex bytes-word))
           (reduce str))
      (clojure.string/replace #"0x" "")
      (keyword)))
