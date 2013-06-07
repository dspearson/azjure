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

;; ### words-per-block
;; Get the number of words per cipher block
(defn- words-per-block [cipher]
  (/ (bc/blocksize cipher) 32))

;; #### mwpb
;; Memoization of words-per-block
(def mwpb (memoize words-per-block))

;; ### bytes-per-block
(defn- bytes-per-block [cipher]
  (/ (bc/blocksize cipher) 8))

;; ### mbpb
;; Memoization of bytes-per-block
(def mbpb (memoize bytes-per-block))

;; ### +mod32
;; Add a and b mod 32
(defn +mod32 [a b]
  (-> (+ a b)
      (mod 32)))

;; ### +modw
;; Add a and b mod 2<sup>32</sup>
(defn +modw
  ([] 0)
  ([a] a)
  ([a b]
     (-> (+ a b)
         (mod 0x100000000)))
  ([a b & more]
     (reduce +modw (+modw a b) more)))

;; ### -modw
;; Subtract a and b mod 2<sup>32</sup>
(defn -modw [a b]
  (-> (- a b)
      (mod 0x100000000)))