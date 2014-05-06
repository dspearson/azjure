;; ## Twofish
;; Designed to meet the spec at
;; [https://www.schneier.com/paper-twofish-paper.pdf](https://www.schneier.com/paper-twofish-paper.pdf)

(ns org.azjure.cipher.twofish
  (:require [org.azjure.cipher.blockcipher :refer [BlockCipher]]
            [org.azjure.cipher.cipher :refer [Cipher]]
            [org.azjure.libbyte :refer [<<< >>> bytes-word
                                        reverse-bytes word-bytes]]
            [org.azjure.libcrypt :refer [+modw maybe]]))

;; #### q0
;; S-box used during key schedule and MDS creation.
;;
;; Using a byte value as an index into the sbox
;; generates a byte value output
(def q0
  [0xA9 0x67 0xB3 0xE8 0x04 0xFD 0xA3 0x76
   0x9A 0x92 0x80 0x78 0xE4 0xDD 0xD1 0x38
   0x0D 0xC6 0x35 0x98 0x18 0xF7 0xEC 0x6C
   0x43 0x75 0x37 0x26 0xFA 0x13 0x94 0x48
   0xF2 0xD0 0x8B 0x30 0x84 0x54 0xDF 0x23
   0x19 0x5B 0x3D 0x59 0xF3 0xAE 0xA2 0x82
   0x63 0x01 0x83 0x2E 0xD9 0x51 0x9B 0x7C
   0xA6 0xEB 0xA5 0xBE 0x16 0x0C 0xE3 0x61
   0xC0 0x8C 0x3A 0xF5 0x73 0x2C 0x25 0x0B
   0xBB 0x4E 0x89 0x6B 0x53 0x6A 0xB4 0xF1
   0xE1 0xE6 0xBD 0x45 0xE2 0xF4 0xB6 0x66
   0xCC 0x95 0x03 0x56 0xD4 0x1C 0x1E 0xD7
   0xFB 0xC3 0x8E 0xB5 0xE9 0xCF 0xBF 0xBA
   0xEA 0x77 0x39 0xAF 0x33 0xC9 0x62 0x71
   0x81 0x79 0x09 0xAD 0x24 0xCD 0xF9 0xD8
   0xE5 0xC5 0xB9 0x4D 0x44 0x08 0x86 0xE7
   0xA1 0x1D 0xAA 0xED 0x06 0x70 0xB2 0xD2
   0x41 0x7B 0xA0 0x11 0x31 0xC2 0x27 0x90
   0x20 0xF6 0x60 0xFF 0x96 0x5C 0xB1 0xAB
   0x9E 0x9C 0x52 0x1B 0x5F 0x93 0x0A 0xEF
   0x91 0x85 0x49 0xEE 0x2D 0x4F 0x8F 0x3B
   0x47 0x87 0x6D 0x46 0xD6 0x3E 0x69 0x64
   0x2A 0xCE 0xCB 0x2F 0xFC 0x97 0x05 0x7A
   0xAC 0x7F 0xD5 0x1A 0x4B 0x0E 0xA7 0x5A
   0x28 0x14 0x3F 0x29 0x88 0x3C 0x4C 0x02
   0xB8 0xDA 0xB0 0x17 0x55 0x1F 0x8A 0x7D
   0x57 0xC7 0x8D 0x74 0xB7 0xC4 0x9F 0x72
   0x7E 0x15 0x22 0x12 0x58 0x07 0x99 0x34
   0x6E 0x50 0xDE 0x68 0x65 0xBC 0xDB 0xF8
   0xC8 0xA8 0x2B 0x40 0xDC 0xFE 0x32 0xA4
   0xCA 0x10 0x21 0xF0 0xD3 0x5D 0x0F 0x00
   0x6F 0x9D 0x36 0x42 0x4A 0x5E 0xC1 0xE0])

;; #### q1
;; S-box used during key schedule and MDS creation.
;;
;; Using a byte value as an index into the sbox
;; generates a byte value output
(def q1
  [0x75 0xF3 0xC6 0xF4 0xDB 0x7B 0xFB 0xC8
   0x4A 0xD3 0xE6 0x6B 0x45 0x7D 0xE8 0x4B
   0xD6 0x32 0xD8 0xFD 0x37 0x71 0xF1 0xE1
   0x30 0x0F 0xF8 0x1B 0x87 0xFA 0x06 0x3F
   0x5E 0xBA 0xAE 0x5B 0x8A 0x00 0xBC 0x9D
   0x6D 0xC1 0xB1 0x0E 0x80 0x5D 0xD2 0xD5
   0xA0 0x84 0x07 0x14 0xB5 0x90 0x2C 0xA3
   0xB2 0x73 0x4C 0x54 0x92 0x74 0x36 0x51
   0x38 0xB0 0xBD 0x5A 0xFC 0x60 0x62 0x96
   0x6C 0x42 0xF7 0x10 0x7C 0x28 0x27 0x8C
   0x13 0x95 0x9C 0xC7 0x24 0x46 0x3B 0x70
   0xCA 0xE3 0x85 0xCB 0x11 0xD0 0x93 0xB8
   0xA6 0x83 0x20 0xFF 0x9F 0x77 0xC3 0xCC
   0x03 0x6F 0x08 0xBF 0x40 0xE7 0x2B 0xE2
   0x79 0x0C 0xAA 0x82 0x41 0x3A 0xEA 0xB9
   0xE4 0x9A 0xA4 0x97 0x7E 0xDA 0x7A 0x17
   0x66 0x94 0xA1 0x1D 0x3D 0xF0 0xDE 0xB3
   0x0B 0x72 0xA7 0x1C 0xEF 0xD1 0x53 0x3E
   0x8F 0x33 0x26 0x5F 0xEC 0x76 0x2A 0x49
   0x81 0x88 0xEE 0x21 0xC4 0x1A 0xEB 0xD9
   0xC5 0x39 0x99 0xCD 0xAD 0x31 0x8B 0x01
   0x18 0x23 0xDD 0x1F 0x4E 0x2D 0xF9 0x48
   0x4F 0xF2 0x65 0x8E 0x78 0x5C 0x58 0x19
   0x8D 0xE5 0x98 0x57 0x67 0x7F 0x05 0x64
   0xAF 0x63 0xB6 0xFE 0xF5 0xB7 0x3C 0xA5
   0xCE 0xE9 0x68 0x44 0xE0 0x4D 0x43 0x69
   0x29 0x2E 0xAC 0x15 0x59 0xA8 0x0A 0x9E
   0x6E 0x47 0xDF 0x34 0x35 0x6A 0xCF 0xDC
   0x22 0xC9 0xC0 0x9B 0x89 0xD4 0xED 0xAB
   0x12 0xA2 0x0D 0x52 0xBB 0x02 0x2F 0xA9
   0xD7 0x61 0x1E 0xB4 0x50 0x04 0xF6 0xC2
   0x16 0x25 0x86 0x56 0x55 0x09 0xBE 0x91])

;; #### sks0
;; Subkey generation steps
(def sks0
  [0x00000000 0x02020202 0x04040404 0x06060606
   0x08080808 0x0a0a0a0a 0x0c0c0c0c 0x0e0e0e0e
   0x10101010 0x12121212 0x14141414 0x16161616
   0x18181818 0x1a1a1a1a 0x1c1c1c1c 0x1e1e1e1e
   0x20202020 0x22222222 0x24242424 0x26262626])

;; #### sks1
;; Subkey generation steps
(def sks1
  [0x01010101 0x03030303 0x05050505 0x07070707
   0x09090909 0x0b0b0b0b 0x0d0d0d0d 0x0f0f0f0f
   0x11111111 0x13131313 0x15151515 0x17171717
   0x19191919 0x1b1b1b1b 0x1d1d1d1d 0x1f1f1f1f
   0x21212121 0x23232323 0x25252525 0x27272727])

;; #### qvec0-4
;; Vectors of q constants (0 or 1) used
;; to identify which q S-box to use above
;; when substituting a value.
(def qvec0 [1 0 1 0])
(def qvec1 [0 0 1 1])
(def qvec2 [0 1 0 1])
(def qvec3 [(bit-xor (nth qvec1 0) 1)
            (bit-xor (nth qvec1 1) 1)
            (bit-xor (nth qvec1 2) 1)
            (bit-xor (nth qvec1 3) 1)])
(def qvec4 [1 0 0 1])

;; #### qarr
;; An array of q constants
(def qarr [qvec0 qvec1 qvec2 qvec3 qvec4])

;; ### getq
;; Get the q vector associated with the given
;; <em>qconst</em> value (0 or 1).
(defn- getq [qconst]
  (if (zero? qconst) q0 q1))

;; #### mgetq
;; Memoization of getq
(def mgetq (memoize getq))

;; ### lfsr1
;; Linear feedback shift register 
;; used during MDS generation
;;
;; Evaluates to a byte
(defn- lfsr1 [byte]
  (bit-xor
    (bit-shift-right byte 1)
    (if (bit-test byte 0) 0xb4 0)))

;; ### lfsr2
;; Linear feedback shift register 
;; used during MDS generation
;;
;; Evaluates to a byte
(defn- lfsr2 [byte]
  (bit-xor
    (bit-shift-right byte 2)
    (if (bit-test byte 1) 0xb4 0)
    (if (bit-test byte 0) 0x5a 0)))

;; ### mx_x
;; Used during MDS generation
;;
;; Evaluates to a byte
(defn- mx_x [byte]
  (bit-xor byte (lfsr2 byte)))

;; ### mx_y
;; Used during MDS generation
;;
;; Evaluates to a byte
(defn- mx_y [byte]
  (bit-xor (mx_x byte) (lfsr1 byte)))

;; ### genmdswords
;; Generate 4 MDS words given a vector
;; of 6 polynomial values.
;;
;; Evaluates to a vector of 4 32-bit
;; words
(defn- genmdswords [[j0 j1 x0 x1 y0 y1]]
  [(bytes-word [y1 y1 x1 j1])
   (bytes-word [j0 x0 y0 y0])
   (bytes-word [y1 j1 y1 x1])
   (bytes-word [x0 y0 j0 x0])])

;; ### mdsround
;; Generate 4 MDS words and conj them
;; onto the MDS vector.
;;
;; Evaluates to a vector of the given
;; MDS values conj'd with the newly
;; calculated values
(defn- mdsround [mdsvec round]
  (let [mdspoly (juxt identity mx_x mx_y)]
    (->> (mdspoly (nth q1 round))
         (interleave (mdspoly (nth q0 round)))
         (vec)
         (genmdswords)
         (reduce conj mdsvec))))

;; ### mds
;; Generate 1024 (2<sup>8</sup> * 4) words to
;; use during MDS multiplication
(defn- mds []
  (reduce mdsround [] (range 256)))

;; #### mmds
;; Memoization of mds
(def mmds (memoize mds))

;; ### ax
;; Calculates αx for a byte
;;
;; Evaluates to a byte
(defn- ax [byte]
  (bit-xor
    (bit-shift-left byte 1)
    (if (bit-test byte 7) 0x14D 0)))

;; ### invax
;; Calculates (1/α)x for a byte
;;
;; Evaluates to a byte
(defn- invax [byte]
  (bit-xor
    (bit-shift-right byte 1)
    (if (bit-test byte 0) (bit-shift-right 0x14D 1) 0)))

;; ### axinvax
;; Calculates (α + 1/α)x for a byte.
;;
;; Evaluates to a byte
(defn- axinvax [byte]
  (bit-xor (ax byte) (invax byte)))

;; ### rs-poly
;; Calcutate the Reed Solomon polynomial over
;; a given 32-bit word. α is the constant 0x14D
;;
;; > x<sup>4</sup> + (α + 1/α)x<sup>3</sup> + αx<sup>2</sup> + (α + 1/α)x + 1
;;
;; Evaluates to a 32-bit word
(defn- rs-poly [word _]
  (let [x (bit-shift-right word 24)]
    (bit-xor
      (bit-and (bit-shift-left word 8) 0xFFFFFFFF)
      (bit-shift-left (axinvax x) 24)
      (bit-shift-left (ax x) 16)
      (bit-shift-left (axinvax x) 8)
      x)))

;; ### rsmm
;; Reed-Solomon matrix multiply.  Two input 32-bit words 
;; are used to calculate a 32-bit output word
;;
;; Evaluates to a 32-bit word
(defn- rsmm [w0 w1]
  (let [r (range 4)]
    (reduce rs-poly (bit-xor w0 (reduce rs-poly w1 r)) r)))

;; ### genSv
;; Generate the S vector
;;
;; Evaluates to a vector of <em>n</em> 32-bit words where
;; <em>n</em> is the number of 64-bit blocks in the
;; key
(defn- genSv [[me mo]]
  (mapv rsmm me mo))

;; ### qsub
;; One q S-box substitution
;;
;; Evaluates to a byte
(defn- qsub [byte km qconst]
  (bit-xor (nth (mgetq qconst) byte) km))

;; ### qsubs
;; q S-box substitions
;;
;; Evaluates to a vector of bytes
(defn- qsubs [kw]
  (fn [bv idx]
    (mapv qsub bv (word-bytes (nth kw idx) true) (nth qarr (inc idx)))))

;; ### mulmds
;; Evaluates to a function over the given mds
;;
;; The function takes a vector of bytes as indexs
;; into the MDS vector.
;;
;; Evaluates to a 32-bit word.
(defn- mulmds [mds]
  (fn [idxv]
    (reduce bit-xor (mapv #(nth mds (+ % (* 4 (nth idxv %)))) (range 4)))))

;; ### h
;; The h function as defined in [Section 4.3.2](http://www.schneier.com/paper-twofish-paper.pdf)
;; Evaluates to a function over the mds and a list of words.
;;
;; Given a word and the list of words, evaluates to a 32-bit word
(defn- h [mds kw]
  (fn [word]
    (-> (qsubs kw)
        (reduce (word-bytes word true) (range (dec (count kw)) -1 -1))
        ((mulmds mds)))))

;; ### bodds
;; Calculate a temp vector of words used during
;; the even and odd subkey generation
;;
;; Evaluates to a vector of 32-bit words
(defn- bodds [mds mo]
  (mapv #(<<< % 8) (mapv (h mds mo) sks1)))

;; #### mbodds
;; Memoization of bodds
(def mbodds (memoize bodds))

;; ### even-subkeys
;; Generate the even subkeys
;;
;; Evaluates to a vector of 20 32-bit words
(defn- even-subkeys [mds [me mo]]
  (mapv +modw (mapv (h mds me) sks0) (mbodds mds mo)))

;; #### meven-subkeys
;; Memoization of even-subkeys
(def meven-subkeys (memoize even-subkeys))

;; ### odd-subkeys
;; Generate the odd subkeys
;;
;; Evaluates to a vector of 20 32-bit words
(defn- odd-subkeys [mds [me mo :as memo]]
  (mapv #(<<< % 9) (mapv +modw (meven-subkeys mds memo) (mbodds mds mo))))

;; ### generate-subkeys
;; Generate the 40 subkeys that will be used over
;; the 16 rounds of Twofish plus the input whiten
;; and output whiten steps.
;;
;; Evaluates to a vector of 40 32-bit words
(defn- generate-subkeys [mds memo]
  (-> (meven-subkeys mds memo)
      (interleave (odd-subkeys mds memo))
      (vec)))

;; #### evens
;; Parital that will grab evens from a collection
(def evens (partial take-nth 2))
;; #### odds
;; Comp that will grab odds from a collection
(def odds (comp evens rest))

;; ### memo
;; Split the key into evens (M<sub>e</sub>) 
;; and odds (M<sub>o</sub>) after the bytes 
;; have been reversed
;;
;; Evaluates to a vector of two vectors.  The
;; first vector contains the even elements.  The
;; last vector contains the odd elements.
(defn- memo [key]
  ((juxt evens odds) (mapv reverse-bytes key)))

;; #### mmemo
;; Memoization of the memo function
(def mmemo (memoize memo))

;; ### pad-key
;; Pad the given key to the next appropriate
;; key size
(defn pad-key
  ([key] {:pre [(vector? key) (> (count key) 15) (< (count key) 33)]}
   (let [len (count key)]
     (if (or (= len 16) (= len 24) (= len 32))
       key
       (if (< len 24)
         (into key (take (- 24 len) (cycle [0])))
         (into key (take (- 32 len) (cycle [0]))))))))

;; ### expand-key
;; Expand the key into the subkey vector
;; and the S-box values
;;
;; Evaluates to a map of two vectors. The ks
;; entry contains the key schedule.  The sv
;; entry contains the S-box values.
;;
;;     {:ks [] :sv []}
;;
(defn expand-key [key]
  (let [[key error] (maybe (pad-key key))]
    (if error (throw error))
    (let [key (mapv bytes-word (partition 4 key))]
      {:ks (generate-subkeys (mmds) (mmemo key))
       :sv (vec (reverse (genSv (mmemo key))))})))

;; ### whiten
;; Whiten the given block with material from the 
;; given key schedule.
;;
;;     (whiten ks)
;;
;; should be used for input whitening
;;
;;     (whiten ks 4)
;;
;; should be user for output whitening
;;
;; Evaluates to a vector of four 32-bit words representing
;; the whitened block
(defn- whiten
  ([block ks sidx]
   (mapv bit-xor block (subvec ks sidx (+ 4 sidx))))
  ([block ks]
   (whiten block ks 0)))

;; ### f
;; The function f as defined in [Section 4.1](http://www.schneier.com/paper-twofish-paper.pdf)
;; of the Twofish paper.  Takes two input 32-bit words, the key schedule, the S-box values,
;; and the round
;;
;; Evaluates to a vector of two 32-bit words.
(defn- f [[w0 w1] {:keys [ks sv]} round]
  (let [t0 ((h (mmds) sv) w0)
        t1 ((h (mmds) sv) (<<< w1 8))]
    [(+modw t0 t1 (nth ks (+ 8 (* 2 round))))
     (+modw t0 (* 2 t1) (nth ks (+ 9 (* 2 round))))]))

;; ### encrypt-round
;; Evaluates to a function over the given round material (the key schedule and
;; S-box values)
;;
;; Each round takes a block and the round number.  The Twofish encryption round 
;; algorithm is then applied to the block.
;;
;; Evaluates to four 32-bit words representing the state of the block after the
;; given round
(defn- encrypt-round [initmap]
  (fn [[w0 w1 w2 w3] round]
    (let [[f0 f1] (f [w0 w1] initmap round)]
      (reduce conj [(>>> (bit-xor f0 w2) 1) (bit-xor (<<< w3 1) f1)] [w0 w1]))))

;; ### decrypt-round
;; Evaluates to a function over the given round material (the key schedule and
;; S-box values)
;;
;; Each round takes a block and the round number.  The Twofish decryption round 
;; algorithm is then applied to the block.
;;
;; Evaluates to four 32-bit words representing the state of the block after the
;; given round
(defn- decrypt-round [initmap]
  (fn [[w0 w1 w2 w3] round]
    (let [[f0 f1] (f [w2 w3] initmap round)]
      (reduce conj [w2 w3] [(bit-xor (<<< w0 1) f0) (>>> (bit-xor f1 w1) 1)]))))

;; ### encrypt-block

(defn- encrypt-block
  "Encrypt the given block with the given key.
  Evaluates to a vector of four 32-bit words that represent the ciphertext of the block."
  [block {:keys [ks] :as initmap}]
  (mapv reverse-bytes
        (whiten
          (->> (range 16)
               (reduce (encrypt-round initmap) (whiten (mapv reverse-bytes block) ks))
               (partition 2)
               ((juxt last first))
               (reduce into [])) ks 4)))

;; ### decrypt-block

(defn- decrypt-block
  "Decrypt the given block with the given key.
  Evaluates to a vector of four 32-bit words that represent the plaintext of the block."
  [block {:keys [ks] :as initmap}]
  (mapv reverse-bytes
        (whiten
          (reduce (decrypt-round initmap)
                  (->> (whiten (mapv reverse-bytes block) ks 4)
                       (partition 2)
                       ((juxt last first))
                       (reduce into []))
                  (range 15 -1 -1)) ks)))

;; ### process-bytes

(defn- process-bytes
  "Process the given vector of bytes using the values given in the initmap."
  ([bytes {:keys [enc] :as initmap}]
   {:pre [(contains? initmap :ks) (contains? initmap :sv) (contains? initmap :enc)
          (vector? (:ks initmap)) (vector? (:sv initmap))
          (= 40 (count (:ks initmap)))
          (> (count (:sv initmap)) 1) (< (count (:sv initmap)) 5)]}
   (let [encfn (if enc encrypt-block decrypt-block)]
     (->> (encfn (mapv bytes-word (partition 4 bytes)) initmap)
          (mapv word-bytes)
          (reduce into)))))

;; ### Twofish
;; Extend the Cipher, BlockCipher, and StreamCipher protocols 
;; thorough the Twofish record type

(defrecord Twofish []
  Cipher
  (initialize [_ key]
    (expand-key key))
  (keysizes-bytes [_]
    (vec (range 16 33)))
  BlockCipher
  (encrypt-block [_ bytes initmap]
    (process-bytes bytes (conj {:enc true} initmap)))
  (decrypt-block [_ bytes initmap]
    (process-bytes bytes (conj {:enc false} initmap)))
  (blocksize [_] 128))
