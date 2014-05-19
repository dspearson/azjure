(ns azjure.keys)

; 64-bit
(def ^{:doc "64-bit vector of 0's"} key-64-zeros (vec (take 8 (repeat 0))))

(def ^{:doc "64-bit vector of OxFF"} key-64-bf2 (vec (take 8 (repeat 0xFF))))

(def ^{} key-64-bf3 [0x30 0x00 0x00 0x00 0x00 0x00 0x00 0x00])

; 128-bit
(def ^{:doc "128-bit vector of 0's"} key-128-zeros (vec (take 16 (repeat 0))))

; 192-bit
(def ^{:doc "192-bit vector of 0's"} key-192-zeros (vec (take 24 (repeat 0))))

; 256-bit
(def ^{:doc "256-bit vector of 0's"} key-256-zeros (vec (take 32 (repeat 0))))