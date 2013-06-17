;; # Test Keys
;; <em>WARNING!!!</em> Do not use these keys to encrypt
;; anything you wish to keep secret.

;; [f197]: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
;; [R2144]: http://tools.ietf.org/html/rfc2144#appendix-B.1
;; [R2612_10]: http://tools.ietf.org/html/rfc2612#page-10
;; [BF]: http://www.schneier.com/code/vectors.txt
;; [TF]: http://www.schneier.com/paper-twofish-paper.pdf
;; [S20] http://cr.yp.to/snuffle/spec.pdf
;; [HC128]: http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
;; [HC256]: http://www3.ntu.edu.sg/home/wuhj/research/hc/hc256_fse.pdf
;; [RABBIT]: http://tools.ietf.org/rfc/rfc4503.txt
;; [TRI]: http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/trivium/unverified.test-vectors?rev=210&view=markup
(ns ^{:author "Jason Ozias"
      :doc "Test keys vectors"}
  org.azjure.testkeys)

;; ### 40-bit Keys

(def ^{:doc "A sample 40-bit key as a vector of bytes
as defined at [RFC 2144][R2144]"} c5-40-key
  [0x01 0x23 0x45 0x67 0x12])

;; ### 80-bit Keys

(def ^{:doc "80-bits of zeros as a vector of bytes."}
  zeros-80-key
  (vec (take 10 (cycle [0]))))

(def ^{:doc "A sample 80-bit key as a vector of bytes
as defined at [RFC 2144][R2144]"} c5-80-key
  [0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78
   0x23 0x45])

(def ^{:doc "A sample 80-bit key as a vector of bytes
as defined at [Trivium Test Vectors][TRI]"}
  trivium-80-key-0
  [0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00
   0x00 0x00])

;; ### 128-bit Keys

(def ^{:doc "128-bits of zeros as a vector of bytes."} zeros-128-key
  (vec (take 16 (cycle [0]))))

(def ^{:doc "AES 128-bit key as a vector of bytes as
defined in Appendix C.1 in [FIPS 197][f197]"} aes-128-key
  [0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07
   0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f])

(def ^{:doc "CAST5 128-bit key as a vector of bytes as
defined at [RFC 2144][R2144]"} c5-128-key
  [0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78
   0x23 0x45 0x67 0x89 0x34 0x56 0x78 0x9a])

(def ^{:doc "CAST6 128-bit key as a vector of bytes as
defined at [RFC 2612][R2612_10]"} c6-128-key
  [0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
   0x0a 0xf7 0x56 0x47 0xf2 0x9f 0x61 0x5d])

(def ^{:doc "HC-128 128-bit key as a vector of bytes as
defined at [HC-128 Spec][HC128]"}
  hc-128-key
  zeros-128-key)

(def ^{:doc "HC-128 128-bit key as a vector of bytes as
defined at [HC-128 Spec][HC128]"}
  hc-128-key-1
  [0x00 0x00 0x00 0x55 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00])

(def ^{:doc "Rabbit 128-bit key as a vector of bytes as
defined at [Rabbit Spec][RABBIT]"}
  rabbit-128-key-0
  [0x91 0x28 0x13 0x29 0x2E 0x3D 0x36 0xFE
   0x3B 0xFC 0x62 0xF1 0xDC 0x51 0xC3 0xAC])

(def ^{:doc "Rabbit 128-bit key as a vector of bytes as
defined at [Rabbit Spec][RABBIT]"}
  rabbit-128-key-1
  [0x83 0x95 0x74 0x15 0x87 0xE0 0xC7 0x33
   0xE9 0xE9 0xAB 0x01 0xC0 0x9B 0x00 0x43])

(def ^{:doc "TEA 128-bit key as a vector of bytes"}
  tea-128-key
  [0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78
   0x23 0x45 0x67 0x89 0x34 0x56 0x78 0x9a])

(def ^{:doc "Twofish 128-bit key as a vector of bytes as
defined at [Twofish paper][TF]"} tf-128-key zeros-128-key)

(def ^{:doc "Used in many tests"} key-128b c5-128-key)

;; ### 192-bit Keys

(def ^{:doc "AES 192-bit key as a vector of bytes as
defined in Appendix C.2 in [FIPS 197][f197]"} aes-192-key
  (into aes-128-key [0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17]))

(def ^{:doc "CAST6 192-bit key as a vector of bytes as
defined in [RFC 2612][R2612_10]"} c6-192-key
  [0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
   0xbe 0xd0 0xac 0x83 0x94 0x0a 0xc2 0x98
   0xba 0xc7 0x7a 0x77 0x17 0x94 0x28 0x63])

(def ^{:doc "Twofish 192-bit key as a vector of bytes as
defined at [Twofish paper][TF]"} tf-192-key
  [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF
   0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10
   0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77])

;; ### 256-bit Keys
 
(def ^{:doc "256-bits of zeros as a vector of bytes."} zeros-256-key
  (vec (take 32 (cycle [0]))))

(def ^{:doc "AES 256-bit key as a vector of bytes as
defined in Appendix C.3 in [FIPS 197][f197]"} aes-256-key
  (into aes-192-key [0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f]))

(def ^{:doc "CAST6 256-bit key as a vector of bytes as
defined in [RFC 2612][R2612_10]"} c6-256-key
  [0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
   0xbe 0xd0 0xac 0x83 0x94 0x0a 0xc2 0x98
   0x8d 0x7c 0x47 0xce 0x26 0x49 0x08 0x46
   0x1c 0xc1 0xb5 0x13 0x7a 0xe6 0xb6 0x04])

(def ^{:doc "HC-256 256-bit key as a vector of bytes as
defined at [HC-256 Spec][HC256]"}
  hc-256-256-key-1
  [0x00 0x00 0x00 0x55 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00])

(def ^{:doc "Twofish 256-bit key as a vector of bytes as
defined at [Twofish paper][TF]"} tf-256-key
  (into tf-192-key [0x88 0x99 0xAA 0xBB 0xCC 0xDD 0xEE 0xFF]))

;; ### Blowfish Test Keys

(def ^{:doc "A sample 128-bit key as a vector of 4 32-bit words
as defined [Blowfish vectors][BF]"} key-128-1
  [0x01234567 0x89ABCDEF 0xF0E1D2C3 0xB4A59687])
