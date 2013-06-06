;; # Test Keys
;; Test keys for use in test cases.
;;
;; <em>WARNING!!!</em><br/>
;; Do not use these keys to encrypt anything you wish to keep secret.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testkeys)

;; ### key-40b
;; A sample 40-bit key as a vector of bytes as defined at
;; [RFC 2144](http://tools.ietf.org/html/rfc2144#appendix-B.1)
(def key-40b [0x01 0x23 0x45 0x67 0x12])

;; ### key-80b
;; A sample 80-bit key as a vector of bytes as defined at
;; [RFC 2144](http://tools.ietf.org/html/rfc2144#appendix-B.1)
(def key-80b [0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78 0x23 0x45])

;; ### key-128
;; A sample 128-bit key as a vector of 4 32-bit words
;; as defined in Appendix C.1 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-128 [0x00010203 0x04050607 0x08090a0b 0x0c0d0e0f])

(def key-128b1 [0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07
                0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f])
;; ### key-128b
;; A sample 128-bit key as a vector of bytes as defined at
;; [RFC 2144](http://tools.ietf.org/html/rfc2144#appendix-B.1)
(def key-128b [0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78 0x23 0x45 0x67 0x89 0x34 0x56 0x78 0x9a])

;; ### key-128-1
;; A sample 128-bit key as a vector of 4 32-bit words
;; as defined [http://www.schneier.com/code/vectors.txt](http://www.schneier.com/code/vectors.txt)
(def key-128-1 [0x01234567 0x89ABCDEF 0xF0E1D2C3 0xB4A59687])

;; ### key-192
;; A sample 192-bit key as a vector of 6 32-bit words.
;; as defined in Appendix C.2 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-192 (into key-128 [0x10111213 0x14151617]))
(def key-192b (into key-128b1 [0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17]))

;; ### key-256
;; A sampel 256-bit key as a vector of 8 32-bit words.
;; as defined in Appendix C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-256 (into key-192 [0x18191a1b 0x1c1d1e1f]))
(def key-256b (into key-192b [0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f]))
