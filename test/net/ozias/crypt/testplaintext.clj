(ns net.ozias.crypt.testplaintext)

;; ### pt-msg
;; A sample plaintext message.  In this case it is my name as 11 
;; UTF-8 bytes (0x4a61736f63204f7a696173) repeated 16 times to make 11 blocks.
(def pt-1 
  [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
   0x69 0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E
   0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61
   0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61
   0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F
   0x7A 0x69 0x61 0x73 0x4A 0x61 0x73 0x6F
   0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A
   0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69
   0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20
   0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61 0x73
   0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73
   0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
   0x69 0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E
   0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61
   0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61
   0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F
   0x7A 0x69 0x61 0x73 0x4A 0x61 0x73 0x6F
   0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A
   0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69
   0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20
   0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61 0x73
   0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73])

;; ### pt-2
;; The plaintext message defined at 
;; [http://www.schneier.com/code/vectors.txt](http://www.schneier.com/code/vectors.txt) for
;; Chained Block Cipher mode testing.
(def pt-2 
  [0x37 0x36 0x35 0x34 0x33 0x32 0x31 0x20
   0x4E 0x6F 0x77 0x20 0x69 0x73 0x20 0x74
   0x68 0x65 0x20 0x74 0x69 0x6D 0x65 0x20
   0x66 0x6F 0x72 0x20 0x00 0x00 0x00 0x00])

