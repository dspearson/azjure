;; ## libbyte
;; Byte manipulation library
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.libbyte)

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
;; the 4 bytes individually.
;;
;;     (word-bytes 0x12ab1f3b)
;;
;; evaluates to
;; > [0x12 0xab 0x1f 0x3b]
;;
;; This is the inverse of byte-words.
(defn word-bytes [word]
  (mapv #(last-byte (bit-shift-right word %)) (range 24 -1 -8)))

(defn- inv-shift [shift]
  (- 32 shift))

(def minv-shift (memoize inv-shift))

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
(defn <<< [word shift]
  (let [sft (mod shift 32)]
    (if (zero? sft)
      word
      (bit-or 
       (bit-and (bit-shift-left word sft) 0xFFFFFFFF) 
       (bit-shift-right word (minv-shift sft))))))

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
(defn >>> [word shift]
  (<<< word (minv-shift shift)))
