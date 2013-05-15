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

;; ### last-byte
;; Evaluates to the least significant byte of the given word
(defn last-byte [word]
  (bit-and 0xff word))

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
