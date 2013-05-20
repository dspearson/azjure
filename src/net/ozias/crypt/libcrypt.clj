;; ## libcrypt
;; Library functions
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.libcrypt
  (:require [net.ozias.crypt.cipher.blockcipher :as bc]))

;; ### words-per-block
;; Get the number of words per cipher block
(defn- words-per-block [cipher]
  (/ (bc/blocksize cipher) 32))

;; #### mwpb
;; Memoization of words-per-block
(def mwpb (memoize words-per-block))

;; ### +modw
;; Add a and b mod 2<sup>32</sup>
(defn +modw [a b]
  (mod (+ a b) 0x100000000))

;; ### -modw
;; Add a and b mod 2<sup>32</sup>
(defn -modw [a b]
  (mod (- a b) 0x100000000))
