;; # Test Plaintext

;; [F197]: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
;; [R2144]: http://tools.ietf.org/html/rfc2144#appendix-B.1
;; [R2612_10]: http://tools.ietf.org/html/rfc2612#page-10
;; [BF]: http://www.schneier.com/code/vectors.txt
;; [TF]: http://www.schneier.com/paper-twofish-paper.pdf

(ns org.azjure.testplaintext
  "Test plaintext vectors."
  {:author "Jason Ozias"})

;; ### Plaintext Strings

(def ^{:doc "A phrase used in suite tests"} phrase
  "The quick brown fox jumps over the lazy dog.")

;; ### 64-bit Plaintext Blocks

(def ^{:doc "A 64-bit vector of zeros"}
  zeros-64-pt (vec (take 8 (cycle [0]))))

(def ^{:doc "A sample plaintext block as a vector of bytes
as defined at [RFC2144][R2144]"}
  c5-pt
  [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF])

(def ^{:doc "A sample plaintex block as  a vector of bytes"}
  tea-64-pt-0
  [0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08])

(def ^{:doc "A sample plaintex block as  a vector of bytes"}
  xtea-64-pt-0
  [0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08])

(def ^{:doc "A sample plaintex block as  a vector of bytes"}
  xtea-64-pt-1
  [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01])

(def ^{:doc "A sample plaintex block as  a vector of bytes"}
  xtea-64-pt-2
  [0x01 0x01 0x01 0x01 0x01 0x01 0x01 0x01])

(def ^{:doc "A sample plaintex block as  a vector of bytes"}
  xtea-64-pt-3
  [0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef])

(def ^{:doc "A sample plaintex block as  a vector of bytes"}
  xtea-64-pt-4
  [0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41])

;; ### 128-bit Plaintext Blocks

(def ^{:doc "A 16-byte vector of zeros."} zeros
  (vec (take 16 (cycle [0]))))

(def ^{:doc "A sample plaintext block as a vector of 16 bytes
as defined in Appendix C.1, C.2, and C.3 in [FIPS 197][F197]"} aes-pt
  [0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77
   0x88 0x99 0xaa 0xbb 0xcc 0xdd 0xee 0xff])

(def ^{:doc "A sample plaintext block as a vector of 16 bytes
as defined in [RFC2612][R2612_10]"} c6-pt zeros)

(def ^{:doc "A sample plaintext block as a vector of 16 bytes
as defined in [Twofish paper][TF]"} tf-pt zeros)

;; ### 384-bit Plaintext Blocks

(def ^{:doc "A 48-byte vector of zeros."} zeros-48
  (vec (take 48 (cycle [0]))))

;; ### 512-bit Plaintext Blocks

(def ^{:doc "A 64-byte vector of zeros."} zeros-64
  (vec (take 64 (cycle [0]))))

;; ### 8192-bit Plaintext Blocks

(def ^{:doc "A 512-byte vector of zeros."}
  zeros-512
  (vec (take 512 (cycle [0]))))

;; ### Other Plaintext Blocks

(def ^{:doc " A sample plaintext message.  In this case it is my name as 11 UTF-8
bytes (0x4a61736f63204f7a696173) repeated 16 times to make 11 blocks."} pt-1
  [0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
   0x69 0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E
   0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61
   0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61
   0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F
   0x7A 0x69 0x61 0x73 0x4A 0x61 0x73 0x6F
   0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A
   0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69
   0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20
   0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61 0x73
   0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73
   0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A
   0x69 0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E
   0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61
   0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61
   0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20 0x4F
   0x7A 0x69 0x61 0x73 0x4A 0x61 0x73 0x6F
   0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73 0x4A
   0x61 0x73 0x6F 0x6E 0x20 0x4F 0x7A 0x69
   0x61 0x73 0x4A 0x61 0x73 0x6F 0x6E 0x20
   0x4F 0x7A 0x69 0x61 0x73 0x4A 0x61 0x73
   0x6F 0x6E 0x20 0x4F 0x7A 0x69 0x61 0x73])

(def ^{:doc "The plaintext message defined at [Blowfish vectors][BF] for
Chained Block Cipher mode testing."} pt-2
  [0x37 0x36 0x35 0x34 0x33 0x32 0x31 0x20
   0x4E 0x6F 0x77 0x20 0x69 0x73 0x20 0x74
   0x68 0x65 0x20 0x74 0x69 0x6D 0x65 0x20
   0x66 0x6F 0x72 0x20 0x00 0x00 0x00 0x00])
