(ns net.ozias.crypt.cipher.helpers)

(defn s-to-hex [s]
  (Long/toHexString s))

(defn to-hex [v]
  (mapv #(Long/toHexString %) v))

(defn filter-exclude [r ex] 
   "Take all indices execpted ex" 
    (filter #(not (ex %)) (range r))) 

(defn dissoc-idx [v & ds]
   (map v (filter-exclude (count v) (into #{} ds))))
