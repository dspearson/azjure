(ns azjure.padders
  (:require [azjure.core :refer :all]))

(defmethod pad :zero [m bv]
  (->> (cycle [0])
       (take (bytes-to-pad (count bv) (bytes-per-block (:type m))))
       (reduce conj bv)))

(defmethod unpad :zero [_ bv]
  (->> (reverse bv)
       (drop-while zero?)
       (reverse)
       (vec)))

(defmethod pad :x923 [m bv]
  (let [btp (bytes-to-pad (count bv) (bytes-per-block (:type m)))
        zeropad (reduce conj bv (take btp (cycle [0])))]
    (assoc zeropad (dec (count zeropad)) btp)))

(defmethod unpad :x923 [bv]
  (subvec bv 0 (- (count bv) (last bv))))