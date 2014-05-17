(ns azjure.padders
  {:author "Jason Ozias"}
  (:require [azjure.cipher.blockcipher :refer :all]))

(defmulti pad
          "Takes an initmap and a vector of bytes and pads it appropriately to
  a multiple of the block size of the cipher.  All padding methods should
  implement this method."
          {:arglists '([m bv])
           :added    "0.2.0"}
          :pad)

(defmulti unpad
          "Takes a vector of bytes and unpads it.  All padding methods should
   implement this method."
          {:arglists '([_ bv])
           :added    "0.2.0"}
          :pad)

(defn- bytes-to-pad
  "Calculate the remaining number of bytes to add to make a full block.

  (bytes-to-pad 15 16) => 1
  (bytes-to-pad 16 16) => 0
  (bytes-to-pad 17 16) => 15"
  {:added "0.2.0"}
  [total-bytes bytes-per-block]
  (let [x (mod total-bytes bytes-per-block)]
    (if (zero? x)
      x
      (- bytes-per-block x))))

(defmethod pad :iso7816 [m bv]
  (let [l (count bv)
        rem (bytes-to-pad l (bytes-per-block m))]
    (if (zero? rem)
      bv
      (let [zeropad (reduce conj bv (take rem (cycle [0])))]
        (assoc zeropad l 0x80)))))

(defmethod unpad :iso7816 [_ bv]
  (->> (reverse bv)
       (drop-while zero?)
       (drop-while #(= 128 %))
       (reverse)
       (vec)))

(defmethod pad :iso10126 [m bv]
  (let [rem (bytes-to-pad (count bv) (bytes-per-block m))
        randompad (reduce conj bv (repeatedly rem #(rand-int 256)))]
    (assoc randompad (dec (count randompad)) rem)))

(defmethod unpad :iso10126 [_ bv]
  (subvec bv 0 (- (count bv) (last bv))))

(defmethod pad :pkcs7 [m bv]
  (let [rem (bytes-to-pad (count bv) (bytes-per-block m))]
    (reduce conj bv (take rem (cycle [rem])))))

(defmethod unpad :pkcs7 [_ bv]
  (subvec bv 0 (- (count bv) (last bv))))

(defmethod pad :x923 [m bv]
  (let [btp (bytes-to-pad (count bv) (bytes-per-block m))
        zeropad (reduce conj bv (take btp (cycle [0])))]
    (assoc zeropad (dec (count zeropad)) btp)))

(defmethod unpad :x923 [_ bv]
  (subvec bv 0 (- (count bv) (last bv))))

(defmethod pad :zero [m bv]
  (->> (cycle [0])
       (take (bytes-to-pad (count bv) (bytes-per-block m)))
       (reduce conj bv)))

(defmethod unpad :zero [_ bv]
  (->> (reverse bv)
       (drop-while zero?)
       (reverse)
       (vec)))