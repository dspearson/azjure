(ns org.ozias.cljlibs.azjure.padding.x923
  (:require [org.ozias.cljlibs.azjure.core :refer :all]))

(defn- pad-bytes
  "Pad the given vector of bytes to the appropriate block size as defined by the
  cipher.

  Evaluates to a vector of bytes"
  [m bv]
  (let [btp (bytes-to-pad (count bv) (bytes-per-block (:type m)))
        zeropad (reduce conj bv (take btp (cycle [0])))]
    (assoc zeropad (dec (count zeropad)) btp)))

(defn- unpad-bytes
  "Unpad the given vector of bytes.

  Evaluates to a vector of bytes."
  [bv]
  (subvec bv 0 (- (count bv) (last bv))))

(defmethod pad :x923 [m bv] (pad-bytes m bv))
(defmethod unpad :x923 [_ bv] (unpad-bytes bv))