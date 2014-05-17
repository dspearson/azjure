(ns azjure.keys)

; 128-bit
(def ^{:doc "128-bit vector of 0's"} key-128-zeros (vec (take 16 (repeat 0))))

(def ^{:doc "128-bit AES test vector key as defined in Appendix C.1 in
  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"}
  key-128-aes
  [0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07
   0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f])

; 192-bit
(def ^{:doc "192-bit vector of 0's"} key-192-zeros (vec (take 24 (repeat 0))))

(def ^{:doc "192-bit AES test vector key as defined in Appendix C.2 in
  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"}
  key-192-aes
  (into key-128-aes [0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17]))

; 256-bit
(def ^{:doc "256-bit vector of 0's"} key-256-zeros (vec (take 32 (repeat 0))))

(def ^{:doc "256-bit AES test vector key as defined in Appendix C.2 in
  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"}
  key-256-aes
  (into key-192-aes [0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f]))