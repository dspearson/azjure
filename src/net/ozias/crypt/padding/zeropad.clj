(ns net.ozias.crypt.padding.zeropad
  (:require [net.ozias.crypt.padding.pad :refer (Pad)]
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;;(reduce conj testvec (take (mod (count testvec) 4) (cycle [0])))

(defn- remaining [cnt multiple]
  (- multiple (rem cnt multiple)))

(defn- bytes-word [vec]
  (apply bit-or 
         (map #(bit-shift-left (nth vec %1) %2) 
              (range 4) 
              (range 24 -1 -8))))

(defn- pad-bytes [unpadded cipher]
  (let [words-per-block (/ (bc/blocksize cipher) 32)
        bytes-per-block (/ (bc/blocksize cipher) 8)]
    (mapv 
     #(bytes-word %)
     (partition 
      (/ bytes-per-block words-per-block) 
      (reduce 
       conj unpadded 
       (take (remaining (count unpadded) bytes-per-block) (cycle [0])))))))

(defrecord Zeropad []
  Pad
  (pad-blocks [_ unpadded cipher]
    (pad-bytes (vec unpadded) cipher)))
