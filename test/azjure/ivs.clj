(ns azjure.ivs)

; 128-bit
(def ^{:doc "128-bit vector of 0's"} iv-128-zeros (vec (take 16 (repeat 0))))

(def ^{:doc "128-bit IV"}
  iv-128-default
  [0x0f 0x0e 0x0d 0x0c 0x0b 0x0a 0x09 0x08
   0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00])

; 192-bit
(def ^{:doc "192-bit vector of 0's"} iv-192-zeros (vec (take 24 (repeat 0))))

; 256-bit
(def ^{:doc "256-bit vector of 0's"} iv-256-zeros (vec (take 32 (repeat 0))))