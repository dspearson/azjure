;; ## Salsa20
;; Designed to meet the [Salsa20 Spec](http://cr.yp.to/snuffle/spec.pdf) spec
(ns net.ozias.crypt.cipher.salsa20
  (:require (net.ozias.crypt.cipher [cipher :refer (Cipher)]
                                    [streamcipher :refer [StreamCipher]])
            [net.ozias.crypt.libcrypt :refer (+modw to-hex)]
            [net.ozias.crypt.libbyte :refer (<<< bytes-word word-bytes dword-bytes)]))

(def sigma
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x33]
   [0x32 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(def tau
  [[0x65 0x78 0x70 0x61]
   [0x6E 0x64 0x20 0x31]
   [0x36 0x2D 0x62 0x79]
   [0x74 0x65 0x20 0x6B]])

(defn- quarterround [[y0 y1 y2 y3]]
  (let [z1 (bit-xor y1 (<<< (+modw y0 y3) 7))
        z2 (bit-xor y2 (<<< (+modw z1 y0) 9))
        z3 (bit-xor y3 (<<< (+modw z2 z1) 13))
        z0 (bit-xor y0 (<<< (+modw z3 z2) 18))]
    [z0 z1 z2 z3]))

(defn- rowround [[y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]]
  (let [[z0 z1 z2 z3] (quarterround [y0 y1 y2 y3])
        [z5 z6 z7 z4] (quarterround [y5 y6 y7 y4])
        [z10 z11 z8 z9] (quarterround [y10 y11 y8 y9])
        [z15 z12 z13 z14] (quarterround [y15 y12 y13 y14])]
    [z0 z1 z2 z3 z4 z5 z6 z7 z8 z9 z10 z11 z12 z13 z14 z15]))
  
(defn- columnround [[x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15]]
  (let [[y0 y4 y8 y12] (quarterround [x0 x4 x8 x12])
        [y5 y9 y13 y1] (quarterround [x5 x9 x13 x1])
        [y10 y14 y2 y6] (quarterround [x10 x14 x2 x6])
        [y15 y3 y7 y11] (quarterround [x15 x3 x7 x11])]
    [y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15]))

(defn- doubleround [x _]
  (rowround (columnround x)))

(defn- salsa20 [in]
  (let [x (mapv #(bytes-word % true) (partition 4 in))]
    (->> (range 10)
         (reduce doubleround x)
         (mapv +modw x)
         (mapv #(word-bytes % true))
         (reduce into))))

(defn- key256? [key]
  (= 32 (count key)))

(defn- key-stream [{:keys [key]} iv]
  (let [c (if (key256? key) sigma tau)
        k0 (subvec key 0 16)
        k1 (if (key256? key) (subvec key 16 32) (subvec key 0 16))]
    (salsa20 (reduce into [(nth c 0) k0 (nth c 1) iv (nth c 2) k1 (nth c 3)]))))

;; ### Salsa20
;; Extend the StreamCipher protocol thorough the Salsa20 record type
(defrecord Salsa20 []
  Cipher
  (initialize [_ key]
    {:key key})
  (keysizes-bytes [_]
    [16 32])
  StreamCipher
  (generate-keystream [_ initmap iv]
    (key-stream initmap iv))
  (keystream-size-bytes [_] 64)
  (iv-size-bytes [_] 16))
