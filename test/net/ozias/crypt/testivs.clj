;; # Test Initialization Vectors
;; Initialization vectors for use in test cases.
;;
;; <em>WARNING!!</em><br/>
;; Do not use these initialization vectors to encrypt 
;; anything you wish to keep secret.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testivs)

;; ### iv-128
;; A sample 128-bit initialization vector as a vector of 4 32-bit words.
(def iv-128 [0x0f0e0d0c 0x0b0a0908 0x07060504 0x03020100])

;; ### iv-128b
;; A sample 128-bit initialization vector as a vector of 16 8-bit bytes.
(def iv-128b [0x0f 0x0e 0x0d 0x0c 0x0b 0x0a 0x09 0x08
              0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00])

;; ### iv-128-1
;; A sample 128-bit initialization vector as a vector of 4 32-bit words.
(def iv-128-1 [0x03020100 0x0f0e0d0c 0x0b0a0908 0x07060504])

;; ### iv-64
;; A sample 64-bit initialization vector as a vector of 2 32-bit words.
;; Defined in [http://www.schneier.com/code/vectors.txt](http://www.schneier.com/code/vectors.txt)
(def iv-64 [0xFEDCBA98 0x76543210])

;; ### iv-64b
;; A sample 64-bit initialization vector as a vector of bytes.
(def iv-64b [0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10])
