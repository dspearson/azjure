(ns azjure.ciphertext)

; Ciphertext generated with 64-bit keys
(def ^{:doc "Blowfish cipher text 1 as defined at
  https://www.schneier.com/code/vectors.txt"}
  ct-64-bf1
  [0x4E 0xF9 0x97 0x45 0x61 0x98  0xDD 0x78])

(def ^{:doc "Blowfish cipher text 2 as defined at
  https://www.schneier.com/code/vectors.txt"}
  ct-64-bf2
  [0x51 0x86 0x6F 0xD5 0xB8 0x5E 0xCB 0x8A])

(def ^{}
  ct-64-bf3
  [0x7D 0x85 0x6F 0x9A 0x61 0x30 0x63 0xF2])

; Ciphertext generated with 128-bit keys

; Ciphertext generated with 192-bit keys

; Ciphertext generated with 256-bit keys