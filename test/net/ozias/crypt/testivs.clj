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

;; ### iv-128-1
;; A sample 128-bit initialization vector as a vector of 4 32-bit words.
(def iv-128-1 [0x03020100 0x0f0e0d0c 0x0b0a0908 0x07060504])

;; ### bf-iv-64
;; A sample 64-bit initialization vector as a vector of 2 32-bit words.
;; Defined in [http://www.schneier.com/code/vectors.txt](http://www.schneier.com/code/vectors.txt)
(def bf-iv-64 [0xFEDCBA98 0x76543210])
