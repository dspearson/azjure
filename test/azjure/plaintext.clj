(ns azjure.plaintext)

; 64-bit
(def ^{:doc "64-bit test vector of zeroes."}
  pt-64-zeroes
  (vec (take 8 (repeat 0))))

(def ^{} pt-64-bf2 (vec (take 8 (repeat 0xFF))))

(def ^{} pt-64-bf3 [0x10 0x00 0x00 0x00 0x00 0x00 0x00 0x01])

; 128-bit

; Other
(def ^{:doc "Test plaintext"} pt "The quick brown fox jumped over the lazy dog")