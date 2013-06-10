;; # Test Initialization Vectors
;; Initialization vectors for use in test cases.
;;
;; <em>WARNING!!</em><br/>
;; Do not use these initialization vectors to encrypt 
;; anything you wish to keep secret.
(ns ^{:author "Jason Ozias"}
  org.azjure.testivs)

;; ### 64-bit Initialization Vectors

(def ^{:doc "64-bits of zeros as a vector of bytes."} zeros-64-iv
  (vec (take 8 (cycle [0]))))

;; ### 128-bit Initialization Vectors

(def ^{:doc "128-bits of zeros as a vector of bytes."} zeros-128-iv
  (vec (take 16 (cycle [0]))))

(def ^{:doc "HC-128 128-bit IV as a vector of bytes as
defined at [HC-128 Spec][HC128]"} hc-128-iv zeros-128-iv)

(def ^{:doc "HC-128 128-bit IV as a vector of bytes as
defined at [HC-128 Spec][HC128]"} hc-128-iv-1
  [0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00])

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

;; ### iv-32b
;; A sample 32-bit initialization vector as a vector of bytes.
(def iv-32b [0xFE 0xDC 0xBA 0x98])
