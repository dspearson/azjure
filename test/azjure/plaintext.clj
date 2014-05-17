(ns azjure.plaintext)

; 128-bit
(def ^{:doc "128-bit AES test vector plaintext as defined in Appendix C.1, C.2,
  and C.3 in http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"}
  pt-128-aes
  [0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77
   0x88 0x99 0xaa 0xbb 0xcc 0xdd 0xee 0xff])

; Other
(def ^{:doc "Test plaintext"} pt "The quick brown fox jumped over the lazy dog")