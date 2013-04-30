(def key (vector 0x2b 0x7e 0x15 0x16
                 0x28 0xae 0xd2 0xa6
                 0xab 0xf7 0x15 0x88 
                 0x09 0xcf 0x4f 0x3c))

(def expand [])

(defn makeword [coll]
  (bit-or (bit-shift-left (nth coll 0) 24)
          (bit-shift-left (nth coll 1) 16)
          (bit-shift-left (nth coll 2) 8)
          (nth coll 3)))

(defn keyexpand [idx vec]
  (subvec vec (- (count vec) 4)))
