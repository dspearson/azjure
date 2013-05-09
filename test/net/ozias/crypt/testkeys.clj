;; # Test Keys
;; Test keys for use in test cases.
;;
;; <em>WARNING!!!</em><br/>
;; Do not use these keys to encrypt anything you wish to keep secret.
(ns ^{:author "Jason Ozias"}
  net.ozias.crypt.testkeys)

;; ### key-128
;; A sample 128-bit key as a vector of 4 32-bit words
;; as defined in Appendix C.1 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-128 [0x00010203 0x04050607 0x08090a0b 0x0c0d0e0f])

;; ### key-192
;; A sample 192-bit key as a vector of 6 32-bit words.
;; as defined in Appendix C.2 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-192 (into key-128 [0x10111213 0x14151617]))

;; ### key-256
;; A sampel 256-bit key as a vector of 8 32-bit words.
;; as defined in Appendix C.3 in 
;; [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf)
(def key-256 (into key-192 [0x18191a1b 0x1c1d1e1f]))
