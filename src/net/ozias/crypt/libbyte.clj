;; ## libbyte
;; Byte manipulation library
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.libbyte
  (:require [clojure.math.numeric-tower :refer (expt)]))

;; ### get-byte
;; Get byte <em>num</em> out of the given word.  <em>num</em>
;; should be 1-4.
;;
;;     (get-byte 0x11223344 4)
;;
;; evaluates to 0x11
(defn get-byte [num word]
  (let [shift (* 8 (- num 1))
        sftfn (if (= 0 shift) word (bit-shift-right word shift))]
    (bit-and sftfn 0xFF)))

;; ### last-byte
;; Evaluates to the least significant byte of the given word
(defn last-byte [word]
  (bit-and 0xff word))

;; ### bytes-word
;; Takes a vector of 4 bytes and creates
;; one 32-bit word composed of the 4 bytes.
;;
;;     (bytes-word [0x12 0xab 0x1f 0x3b])
;;
;; evaluates to
;; > 0x12ab1f3b
;;
;; This is the inverse of word-bytes.
(defn bytes-word [vec]
  (apply bit-or 
         (map #(bit-shift-left (nth vec %1) %2) 
              (range 4) 
              (range 24 -1 -8))))        

(defn bytes-dword [vec]
  (apply bit-or
         (map #(bit-shift-left (nth vec %1) %2)
              (range 8)
              (range 56 -1 -8))))

;; ### word-bytes
;; Takes a 32-bit word and creates a vector of 
;; the 4 bytes individually. If <em>lsf</em> is true,
;; the order of the vector will be LSB to MSB.
;; Otherwise, the order of the vector will be
;; MSB to LSB.
;;
;;     (word-bytes 0x12ab1f3b)
;;
;; evaluates to
;; > [0x12 0xab 0x1f 0x3b]
;;
;;     (word-bytes 0x12ab1f3b)
;;
;; evaluates to
;; > [0x3b 0x1f 0xab 0x12]
;;
;; This is the inverse of byte-words.
(defn word-bytes 
  ([word lsf]
     (let [rng (if lsf (range 0 32 8) (range 24 -1 -8))]
       (mapv #(last-byte (bit-shift-right word %)) rng)))
  ([word]
     (word-bytes word false)))
 

(defn- inv-shift [shift bits]
  (- bits shift))

(def minv-shift (memoize inv-shift))

(defn shift-dispatch [word shift bits]
  (cond 
   (or (instance? BigInteger word) (> bits 32)) :a 
   :else :default))

;; ### <<<
;; Circular left shift
;;
;; Shift a 32-bit word left by <em>shift</em> bits, shifting
;; the leftmost bits into the rightmost positions.
;;
;;     (<<< 0x12345678 8)
;;
;; evaluates to
;;
;; > 0x34567812
(defmulti <<<-mm shift-dispatch) 

(defmethod <<<-mm :a [word shift bits] 
  (let [biw (if (instance? BigInteger word) word (BigInteger. (str word)))
        sft (mod shift bits)
        mask (BigInteger. (str (- (expt 2 bits) 1)))]
    (if (zero? sft) 
      word
      (.or
       (.and (.shiftLeft biw sft) mask)
       (.shiftRight biw (minv-shift sft bits))))))

(defmethod <<<-mm :default [word shift bits]
  (let [sft (mod shift bits)
        mask (- (expt 2 bits) 1)]
    (if (zero? sft) 
      word
      (bit-or
       (bit-and (bit-shift-left word sft) mask)
       (bit-shift-right word (minv-shift sft bits))))))

(defn <<< 
  ([word shift bits] (<<<-mm word shift bits))
  ([word shift] (<<<-mm word shift 32)))
;;     (let [sft (mod shift bits)
;;           mask (- (expt 2 bits) 1)]
;;       (if (zero? sft) 
;;         word
;;         (cond
;;          (<= bits 32) (bit-or 
;;                       (bit-and (bit-shift-left word sft) mask) 
;;                       (bit-shift-right word (minv-shift sft bits)))
;;          (> bits 32) (.or
;;                       (.and (.shiftLeft (BigInteger. (str word)) sft))
;;                       (.shiftRight (BigInteger. (str word)) (minv-shift sft bits)))
;;  ([word shift]
;;     (<<< word shift 32)))

;; ### >>>
;; Circular right shift
;;
;; Shift a 32-bit word right by <em>shift</em> bits, shifting
;; the rightmost bits into the leftmost positions.
;;
;;     (>>> 0x12345678 8)
;;
;; evaluates to
;;
;; > 0x78123456
(defn >>>
  ([word shift bits]
     (<<< word (minv-shift shift bits)))
  ([word shift]
     (>>> word shift 32)))
