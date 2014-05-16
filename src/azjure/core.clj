(ns azjure.core
  "Encrypt/Decrypt API

  See https://github.com/CraZySacX/azjure for usage"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.encoders :refer :all]
            [azjure.modes :refer :all]
            [azjure.padders :refer :all])
  (:import (java.security SecureRandom)))

(defn encrypt
  "Encrypt the given input i based on the configuration supplied in the map m"
  {:added "0.2.0"}
  [i m]
  (let [m (initialize m)]
    (->> (input-decoder m i)
         (pad m)
         (encrypt-blocks m)
         (output-encoder m))))

(defn decrypt
  "Encrypt the given input i based on the configuration supplied in the map m"
  {:added "0.2.0"}
  [i m]
  (let [m (initialize m)]
    (output-encoder
      m
      (->> (input-decoder m i :encryption false)
           (decrypt-blocks m)
           (unpad m))
      :encryption false)))

(defn gen-key
  "Generate a key of length x bits.  x should be a multiple of 8.

  Evaluates to a vector of unsigned byte values."
  {:added "0.2.0"}
  [x]
  {:pre [(pos? x) (zero? (mod x 8))]}
  (let [barr (byte-array (/ x 8))
        _ (.nextBytes (SecureRandom.) barr)]
    (mapv (partial + 128) (vec barr))))