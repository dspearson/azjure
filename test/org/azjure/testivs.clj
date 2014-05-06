;; # Test Initialization Vectors
;; Initialization vectors for use in test cases.
;;
;; <em>WARNING!!</em><br/>
;; Do not use these initialization vectors to encrypt 
;; anything you wish to keep secret.
;; [RABBIT]: http://tools.ietf.org/rfc/rfc4503.txt
;; [HC256]: http://www3.ntu.edu.sg/home/wuhj/research/hc/hc256_fse.pdf

(ns org.azjure.testivs
  {:author "Jason Ozias"})

;; ### 32-bit Initialization Vectors

(def ^{:doc "A 32-bit initialization vector of zeros as a vector of bytes"}
  zeros-32-iv
  (vec (take 4 (cycle [0]))))

(def ^{:doc "A sample 32-bit initialization vector as a vector of bytes."}
  iv-32b
  [0xFE 0xDC 0xBA 0x98])

;; ### 64-bit Initialization Vectors

(def ^{:doc "64-bits of zeros as a vector of bytes."}
  zeros-64-iv
  (vec (take 8 (cycle [0]))))

(def ^{:doc "A sample 64-bit initialization vector as a vector of bytes."}
  iv-64b
  [0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10])

(def ^{:doc "Rabbit 64-bit IV as a vector of bytes as
defined at [Rabbit Spec][RABBIT]"}
  rabbit-64-iv-0
  [0xC3 0x73 0xF5 0x75 0xC1 0x26 0x7E 0x59])

(def ^{:doc "Rabbit 64-bit IV as a vector of bytes as
defined at [Rabbit Spec][RABBIT]"}
  rabbit-64-iv-1
  [0xA6 0xEB 0x56 0x1A 0xD2 0xF4 0x17 0x27])

;; ### 80-bit Initialization Vectors

(def ^{:doc "80-bits of zeros as a vector of bytes."}
  zeros-80-iv
  (vec (take 10 (cycle [0]))))

(def ^{:doc "80-bits of zeros as a vector of bytes."}
  trivium-80-iv
  [0x00 0x00 0x00 0x00 0x00 0x00 0x80 0x00
   0x00 0x00])

;; ### 96-bit Initialization Vectors

(def ^{:doc "96-bits of zeros as a vector of bytes."}
  zeros-96-iv
  (vec (take 12 (cycle [0]))))

(def ^{:doc "96-bits of as a vector of bytes."}
  grain-96-iv
  [0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
   0x12 0x34 0x56 0x78])

;; ### 128-bit Initialization Vectors

(def ^{:doc "128-bits of zeros as a vector of bytes."}
  zeros-128-iv
  (vec (take 16 (cycle [0]))))

(def ^{:doc "A sample 128-bit initialization vector as a vector of 16 bytes."}
  iv-128b 
  [0x0f 0x0e 0x0d 0x0c 0x0b 0x0a 0x09 0x08
   0x07 0x06 0x05 0x04 0x03 0x02 0x01 0x00])

(def ^{:doc "HC-128 128-bit IV as a vector of bytes as
defined at [HC-128 Spec][HC128]"}
  hc-128-iv
  zeros-128-iv)

(def ^{:doc "HC-128 128-bit IV as a vector of bytes as
defined at [HC-128 Spec][HC128]"} 
  hc-128-iv-1
  [0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00])

;; ### 256-bit Initialization Vectors

(def ^{:doc "256-bits of zeros as a vector of bytes."}
  zeros-256-iv 
  (vec (take 32 (cycle [0]))))

(def ^{:doc "HC-256 256-bit IV as a vector of bytes as
defined at [HC-256 Spec][HC256]"} 
  hc-256-256-iv-1
  [0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00])
