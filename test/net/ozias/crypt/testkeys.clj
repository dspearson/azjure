;; # Test Keys
;; <em>WARNING!!!</em> Do not use these keys to encrypt
;; anything you wish to keep secret.

;; [f197]: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
;; [R2144]: http://tools.ietf.org/html/rfc2144#appendix-B.1
;; [BF]: http://www.schneier.com/code/vectors.txt
;; [TF]: http://www.schneier.com/paper-twofish-paper.pdf
(ns ^{:author "Jason Ozias"
      :doc "Test keys vectors"}
  net.ozias.crypt.testkeys)

;; ### 40-bit Keys

(def ^{:doc "A sample 40-bit key as a vector of bytes
as defined at [RFC 2144][R2144]"} c5-40-key
  [0x01 0x23 0x45 0x67 0x12])

;; ### 80-bit Keys

(def ^{:doc "A sample 80-bit key as a vector of bytes
as defined at [RFC 2144][R2144]"} c5-80-key
  [0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78
   0x23 0x45])

;; ### 128-bit Keys

(def ^{:doc "AES 128-bit key as a vector of bytes as
defined in Appendix C.1 in [FIPS 197][f197]"} aes-128-key
  [0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07
   0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f])

(def ^{:doc "A sample 128-bit key as a vector of bytes 
as defined at [RFC 2144][R2144]"} c5-128-key
  [0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78
   0x23 0x45 0x67 0x89 0x34 0x56 0x78 0x9a])

(def ^{:doc "Twofish 128-bit key as a vector of bytes as
defined at [Twofish paper][TF]"} tf-128-key
  [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00])

(def key-128b c5-128-key)

;; ### 192-bit Keys

(def ^{:doc "AES 192-bit key as a vector of bytes as
defined in Appendix C.2 in [FIPS 197][f197]"} aes-192-key
  (into aes-128-key [0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17]))

(def ^{:doc "Twofish 192-bit key as a vector of bytes as
defined at [Twofish paper][TF]"} tf-192-key
  [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF
   0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10
   0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77])

;; ### 256-bit Keys
 
(def ^{:doc "AES 256-bit key as a vector of bytes as
defined in Appendix C.3 in [FIPS 197][f197]"} aes-256-key
  (into aes-192-key [0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f]))

(def ^{:doc "Twofish 256-bit key as a vector of bytes as
defined at [Twofish paper][TF]"} tf-256-key
  (into tf-192-key [0x88 0x99 0xAA 0xBB 0xCC 0xDD 0xEE 0xFF]))

;; ### Blowfish Test Keys

(def ^{:doc "A sample 128-bit key as a vector of 4 32-bit words
as defined [Blowfish vectors][BF]"} key-128-1
  [0x01234567 0x89ABCDEF 0xF0E1D2C3 0xB4A59687])
