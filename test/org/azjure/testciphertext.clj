;; # Test Ciphertext

;; [F197]: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
;; [TF]: http://www.schneier.com/paper-twofish-paper.pdf
(ns ^{:author "Jason Ozias"
      :doc "Test ciphertext vectors."}
  org.azjure.testciphertext)

;; ### Ciphertext generated with 40-bit keys.

(def ^{:doc "A sample ciphertext block encrypted with the sample 40-bit key
as a vector of bytes as defined in XXX"} c5-40-ct
  [0x7A 0xC8 0x16 0xD1 0x6E 0x9B 0x30 0x2E])

;; ### Ciphertext generated with 80-bit keys.

(def ^{:doc "A sample ciphertext block encrypted with the sample 80-bit key
as a vector of bytes as defined in XXX"} c5-80-ct
  [0xEB 0x6A 0x71 0x1A 0x2C 0x02 0x27 0x1B])

;; ### Ciphertext generated with 128-bit keys.

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in Appendix C.1 in [FIPS 197][F197]"} aes-128-ct
  [0x69 0xc4 0xe0 0xd8 0x6a 0x7b 0x04 0x30
   0xd8 0xcd 0xb7 0x80 0x70 0xb4 0xc5 0x5a])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in XXX"} c5-128-ct
  [0x23 0x8B 0x4F 0xE5 0x84 0x7E 0x44 0xB2])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in [RFC2612][R2612_10]"} c6-128-ct
  [0xc8 0x42 0xa0 0x89 0x72 0xb4 0x3d 0x20
   0x83 0x6c 0x91 0xd1 0xb7 0x53 0x0f 0x6b])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in [Rabbit Spec][RABBIT]"}
  rabbit-128-ct-0
  [0xB1 0x57 0x54 0xF0 0x36 0xA5 0xD6 0xEC
   0xF5 0x6B 0x45 0x26 0x1C 0x4A 0xF7 0x02
   0x88 0xE8 0xD8 0x15 0xC5 0x9C 0x0C 0x39
   0x7B 0x69 0x6C 0x47 0x89 0xC6 0x8A 0xA7
   0xF4 0x16 0xA1 0xC3 0x70 0x0C 0xD4 0x51
   0xDA 0x68 0xD1 0x88 0x16 0x73 0xD6 0x96])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in [Rabbit Spec][RABBIT]"}
  rabbit-128-ct-1
  [0x3D 0x2D 0xF3 0xC8 0x3E 0xF6 0x27 0xA1
   0xE9 0x7F 0xC3 0x84 0x87 0xE2 0x51 0x9C
   0xF5 0x76 0xCD 0x61 0xF4 0x40 0x5B 0x88
   0x96 0xBF 0x53 0xAA 0x85 0x54 0xFC 0x19
   0xE5 0x54 0x74 0x73 0xFB 0xDB 0x43 0x50
   0x8A 0xE5 0x3B 0x20 0x20 0x4D 0x4C 0x5E])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in [Rabbit Spec][RABBIT]"}
  rabbit-128-ct-2
  [0x0C 0xB1 0x0D 0xCD 0xA0 0x41 0xCD 0xAC
   0x32 0xEB 0x5C 0xFD 0x02 0xD0 0x60 0x9B
   0x95 0xFC 0x9F 0xCA 0x0F 0x17 0x01 0x5A
   0x7B 0x70 0x92 0x11 0x4C 0xFF 0x3E 0xAD
   0x96 0x49 0xE5 0xDE 0x8B 0xFC 0x7F 0x3F
   0x92 0x41 0x47 0xAD 0x3A 0x94 0x74 0x28])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in [Rabbit Spec][RABBIT]"}
  rabbit-128-ct-3
  [0xC6 0xA7 0x27 0x5E 0xF8 0x54 0x95 0xD8
   0x7C 0xCD 0x5D 0x37 0x67 0x05 0xB7 0xED
   0x5F 0x29 0xA6 0xAC 0x04 0xF5 0xEF 0xD4
   0x7B 0x8F 0x29 0x32 0x70 0xDC 0x4A 0x8D
   0x2A 0xDE 0x82 0x2B 0x29 0xDE 0x6C 0x1E
   0xE5 0x2B 0xDB 0x8A 0x47 0xBF 0x8F 0x66])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in [Rabbit Spec][RABBIT]"}
  rabbit-128-ct-4
  [0x1F 0xCD 0x4E 0xB9 0x58 0x00 0x12 0xE2
   0xE0 0xDC 0xCC 0x92 0x22 0x01 0x7D 0x6D
   0xA7 0x5F 0x4E 0x10 0xD1 0x21 0x25 0x01
   0x7B 0x24 0x99 0xFF 0xED 0x93 0x6F 0x2E
   0xEB 0xC1 0x12 0xC3 0x93 0xE7 0x38 0x39
   0x23 0x56 0xBD 0xD0 0x12 0x02 0x9B 0xA7])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key
as a vector of bytes as defined in [Rabbit Spec][RABBIT]"}
  rabbit-128-ct-5
  [0x44 0x5A 0xD8 0xC8 0x05 0x85 0x8D 0xBF
   0x70 0xB6 0xAF 0x23 0xA1 0x51 0x10 0x4D
   0x96 0xC8 0xF2 0x79 0x47 0xF4 0x2C 0x5B
   0xAE 0xAE 0x67 0xC6 0xAC 0xC3 0x5B 0x03
   0x9F 0xCB 0xFC 0x89 0x5F 0xA7 0x1C 0x17
   0x31 0x3D 0xF0 0x34 0xF0 0x15 0x51 0xCB])

(def ^{:doc "A sample ciphertext block encrypted with the sample 128-bit key 
as a vector of bytes as defined in [Twofish paper][TF]"} tf-128-ct
  [0x9F 0x58 0x9F 0x5C 0xF6 0x12 0x2C 0x32
   0xB6 0xBF 0xEC 0x2F 0x2A 0xE8 0xC3 0x5A])

;; ### Ciphertext generated with 192-bit keys.

(def ^{:doc "A sample ciphertext block encrypted with the sample 192-bit key
as a vector of bytes as defined in Appendix C.2 in [FIPS 197][F197]"} aes-192-ct
  [0xdd 0xa9 0x7c 0xa4 0x86 0x4c 0xdf 0xe0
   0x6e 0xaf 0x70 0xa0 0xec 0x0d 0x71 0x91])

(def ^{:doc "A sample ciphertext block encrypted with the sample 192-bit key
as a vector of bytes as defined in [RFC2612][R2612_10]"} c6-192-ct
  [0x1b 0x38 0x6c 0x02 0x10 0xdc 0xad 0xcb
   0xdd 0x0e 0x41 0xaa 0x08 0xa7 0xa7 0xe8])

(def ^{:doc "A sample ciphertext block encrypted with the sample 192-bit key
as a vector of bytes as defined in [Twofish paper][TF]"} tf-192-ct
  [0xCF 0xD1 0xD2 0xE5 0xA9 0xBE 0x9C 0xDF
   0x50 0x1F 0x13 0xB8 0x92 0xBD 0x22 0x48])

;; ### Ciphertext generated with 256-bit keys.

(def ^{:doc "A sample ciphertext block encrypted with the sample 256-bit key
as a vector of bytes as defined in Appendix C.3 in [FIPS 197][F197]"} aes-256-ct
  [0x8e 0xa2 0xb7 0xca 0x51 0x67 0x45 0xbf
   0xea 0xfc 0x49 0x90 0x4b 0x49 0x60 0x89])

(def ^{:doc "A sample ciphertext block encrypted with the sample 256-bit key
as a vector of bytes as defined in [RFC2612][R2612_10]"} c6-256-ct
  [0x4f 0x6a 0x20 0x38 0x28 0x68 0x97 0xb9
   0xc9 0x87 0x01 0x36 0x55 0x33 0x17 0xfa])

(def ^{:doc "A sample ciphertext block encrypted with the sample 256-bit key
as a vector of bytes as defined in [Twofish paper][TF]"} tf-256-ct
  [0x37 0x52 0x7B 0xE0 0x05 0x23 0x34 0xB8
   0x9F 0x0C 0xFC 0xCA 0xE8 0x7C 0xFA 0x20])

;; ### Keystreams Generated Ciphertext

(def ^{:doc "A sample 512-bit keystream generated with a sample 
128-bit key/iv pair as a vector of bytes as defined 
in [HC-128 Spec][HC128]"} hc-128-ct
  [0x82 0x00 0x15 0x73 0xA0 0x03 0xFD 0x3B
   0x7F 0xD7 0x2F 0xFB 0x0E 0xAF 0x63 0xAA
   0xC6 0x2F 0x12 0xDE 0xB6 0x29 0xDC 0xA7
   0x27 0x85 0xA6 0x62 0x68 0xEC 0x75 0x8B
   0x1E 0xDB 0x36 0x90 0x05 0x60 0x89 0x81
   0x78 0xE0 0xAD 0x00 0x9A 0xBF 0x1F 0x49
   0x13 0x30 0xDC 0x1C 0x24 0x6E 0x3D 0x6C
   0xB2 0x64 0xF6 0x90 0x02 0x71 0xD5 0x9C])

(def ^{:doc "A sample 512-bit keystream generated with a sample 
128-bit key/iv pair as a vector of bytes as defined 
in [HC-128 Spec][HC128]"} hc-128-ct-1
  [0xD5 0x93 0x18 0xC0 0x58 0xE9 0xDB 0xB7
   0x98 0xEC 0x65 0x8F 0x04 0x66 0x17 0x64
   0x24 0x67 0xFC 0x36 0xEC 0x6E 0x2C 0xC8
   0xA7 0x38 0x1C 0x1B 0x95 0x2A 0xB4 0xC9
   0x23 0xF1 0x3E 0x32 0x8B 0x90 0x6A 0x0A
   0x68 0x7B 0x75 0xCE 0xBB 0xF7 0x14 0x9F
   0x11 0xE0 0xCD 0xE4 0x3F 0x17 0xB5 0xAE
   0x94 0x8C 0x60 0x89 0xCA 0x46 0xCF 0xB5])

(def ^{:doc "A sample 512-bit keystream generated with a sample 
128-bit key/iv pair as a vector of bytes as defined 
in [HC-128 Spec][HC128]"} hc-128-ct-2
  [0xA4 0x51 0x82 0x51 0x0A 0x93 0xB4 0x04
   0x31 0xF9 0x2A 0xB0 0x32 0xF0 0x39 0x06
   0x7A 0xA4 0xB4 0xBC 0x0B 0x48 0x22 0x57
   0x72 0x9F 0xF9 0x2B 0x66 0xE5 0xC0 0xCD
   0x56 0x0C 0x0F 0x31 0xE8 0x83 0xCC 0xD3
   0xEF 0xB8 0x3D 0x66 0x7F 0xE0 0xDF 0x62
   0x90 0x17 0x3E 0x59 0x9C 0xAA 0xCE 0xC5
   0x6F 0x80 0x03 0xAB 0xA0 0xE5 0xA6 0xC9])

(def ^{:doc ""} s20-128-ct 
  [0x9A 0x97 0xF6 0x5B 0x9B 0x4C 0x72 0x1B
   0x96 0x0A 0x67 0x21 0x45 0xFC 0xA8 0xD4
   0xE3 0x2E 0x67 0xF9 0x11 0x1E 0xA9 0x79
   0xCE 0x9C 0x48 0x26 0x80 0x6A 0xEE 0xE6
   0x3D 0xE9 0xC0 0xDA 0x2B 0xD7 0xF9 0x1E
   0xBC 0xB2 0x63 0x9B 0xF9 0x89 0xC6 0x25
   0x1B 0x29 0xBF 0x38 0xD3 0x9A 0x9B 0xDC
   0xE7 0xC5 0x5F 0x4B 0x2A 0xC1 0x2A 0x39])

(def ^{:doc ""} s20-256-ct 
  [0x9A 0x97 0xF6 0x5B 0x9B 0x4C 0x72 0x1B
   0x96 0x0A 0x67 0x21 0x45 0xFC 0xA8 0xD4
   0xE3 0x2E 0x67 0xF9 0x11 0x1E 0xA9 0x79
   0xCE 0x9C 0x48 0x26 0x80 0x6A 0xEE 0xE6
   0x3D 0xE9 0xC0 0xDA 0x2B 0xD7 0xF9 0x1E
   0xBC 0xB2 0x63 0x9B 0xF9 0x89 0xC6 0x25
   0x1B 0x29 0xBF 0x38 0xD3 0x9A 0x9B 0xDC
   0xE7 0xC5 0x5F 0x4B 0x2A 0xC1 0x2A 0x39])

;; ### Other ciphertext

(def ^{:doc "A sample ciphertext message that is the result of encrypting
<em>pt-1</em> in ECB mode with Twofish, key-128b, and iv-128b."} tf-ecb
  [0x4C 0xD1 0xFE 0xC5 0x25 0x60 0x47 0x61
   0x6F 0x82 0xDE 0xBB 0xB3 0x0B 0xCD 0x50
   0x40 0x23 0x22 0x45 0xF0 0xBD 0xFB 0xA2
   0xB9 0x67 0xF1 0x5F 0x5B 0x0F 0x44 0x66
   0xE7 0x19 0x93 0x6F 0x1C 0xA6 0x00 0x10
   0x24 0x3F 0xBA 0xAD 0xA4 0x0D 0xF5 0x41
   0x17 0x5A 0x3E 0xD4 0x9B 0x66 0x46 0xC2
   0xD6 0x92 0xF5 0xD2 0x84 0x41 0x89 0xF1
   0x73 0xCD 0xF2 0x68 0x17 0xB2 0x25 0xA7
   0xE4 0x2E 0xFD 0x07 0xE4 0xC5 0xD1 0xF5
   0x6C 0x0B 0x40 0x49 0xE4 0x71 0x12 0xB4
   0xC9 0xDC 0x42 0x60 0x01 0x72 0x28 0x80
   0x9A 0x0A 0x87 0x35 0x31 0x47 0xB4 0x14
   0x58 0xA6 0x22 0x01 0x67 0xC9 0xF7 0xB3
   0x4F 0x14 0x82 0xB4 0x6F 0x4F 0xF4 0xC5
   0x1C 0xD3 0x58 0xDC 0xBE 0x41 0xB6 0x21
   0x16 0xFF 0x06 0x2E 0xDC 0xC1 0x86 0x1F
   0xCC 0xF1 0x76 0x0D 0x52 0x8F 0xF1 0x83
   0xDA 0x30 0xF8 0x5B 0x09 0x17 0xF9 0x36
   0xC1 0xAF 0x2F 0x5E 0x98 0xAF 0xD8 0x3B
   0x8E 0xD1 0xB3 0x29 0xA7 0x17 0x3F 0x06
   0x53 0x63 0x9A 0x73 0x81 0x0B 0xFB 0x19])

(def ^{:doc "A sample ciphertext message that is the result of encrypting
<em>pt-1</em> in CBC mode with Twofish, key-128b, and iv-128b."} tf-cbc
  [0xC3 0x86 0x86 0x8D 0xC2 0xB2 0x9C 0x91
   0x81 0xD0 0xB3 0x2D 0xEA 0xC2 0x46 0x54
   0x98 0x1C 0x48 0x97 0x80 0x10 0xF5 0x88
   0xD0 0x85 0x7E 0x49 0x36 0x42 0x46 0x6A
   0xC2 0x76 0x24 0x74 0xAA 0x09 0xF9 0x86
   0x65 0xC6 0x54 0x4B 0xDF 0xC2 0x36 0x02
   0xD3 0x25 0x06 0x52 0x30 0xD2 0x34 0xEA
   0xE6 0x55 0xC0 0xC1 0xDA 0xEF 0x95 0xE3
   0x7D 0xB0 0x1B 0xEE 0x43 0x6B 0x9A 0xFD
   0xB1 0xDD 0x9B 0x17 0xD3 0x86 0x36 0xDE
   0xBC 0x3C 0xA9 0xF9 0x92 0xE8 0xAC 0xBC
   0xA5 0x52 0x24 0x00 0x54 0x00 0x33 0x0D
   0x89 0x99 0xBB 0x34 0x42 0xD8 0xD4 0x37
   0x0A 0xD7 0x92 0x7C 0x50 0xE3 0x8E 0x8B
   0xCB 0x61 0x74 0x09 0x5C 0xEE 0x65 0x07
   0xD2 0x97 0x17 0x2E 0x2D 0x5D 0xF1 0x47
   0xCE 0x07 0x36 0x01 0xB3 0xE4 0x51 0x23
   0x69 0x93 0x6B 0x34 0x42 0x30 0xDD 0x59
   0x5D 0x76 0x87 0x85 0x51 0x99 0xD5 0xE3
   0x44 0x6B 0xE6 0x95 0x6D 0x53 0x0F 0x74
   0x59 0x9C 0xC2 0x24 0x76 0x52 0x7F 0x8C
   0x81 0x7F 0x13 0x71 0x38 0xD0 0xB5 0x33])

(def ^{:doc "A sample ciphertext message that is the result of encrypting
<em>pt-1</em> in PCBC mode with Twofish, key-128b, and iv-128b."} tf-pcbc
  [0xC3 0x86 0x86 0x8D 0xC2 0xB2 0x9C 0x91
   0x81 0xD0 0xB3 0x2D 0xEA 0xC2 0x46 0x54
   0xFD 0xB6 0xDC 0x69 0x0B 0x16 0x6C 0x2F
   0x3E 0xBB 0x43 0xFA 0xDF 0x76 0x18 0x66
   0x3C 0x33 0x96 0x2E 0x06 0x62 0xD9 0x0D
   0x36 0xA3 0xBB 0x4A 0x66 0x1F 0x0A 0x2F
   0x1F 0x2F 0x71 0xD5 0xF0 0xE3 0x0D 0x45
   0x99 0x96 0x9E 0x4C 0x33 0xD7 0xB6 0x9E
   0x9F 0x3D 0x91 0x9C 0x8F 0x57 0xD5 0xE1
   0x82 0x67 0x13 0xA1 0x27 0xBE 0xE8 0x72
   0xD6 0x57 0xAC 0xD6 0xB2 0x09 0xF0 0xDC
   0x52 0x9C 0x43 0xAF 0xB6 0x09 0x48 0x33
   0x90 0x92 0xEA 0x68 0x3F 0x97 0xC8 0x15
   0x89 0x81 0x35 0x62 0xE7 0xCF 0xEE 0xE2
   0x75 0xC3 0x33 0xFE 0x00 0x75 0x08 0x65
   0x62 0x6D 0x48 0x6A 0xF5 0xD6 0x18 0xA0
   0xCF 0xF4 0x79 0xE5 0x7B 0x1E 0x1A 0x9F
   0x36 0x91 0xB5 0xD6 0x7C 0xC0 0x5B 0xA2
   0x15 0xB6 0x6C 0xEC 0x68 0xF0 0x15 0xF4
   0xA2 0x11 0x2F 0xDF 0x31 0xF2 0x97 0xF7
   0x10 0xBE 0xB4 0xF5 0xDC 0x8D 0xA9 0x97
   0xA6 0xFE 0x7A 0x70 0x58 0xFF 0xDB 0x1F])

(def ^{:doc "A sample ciphertext message that is the result of encrypting
<em>pt-1</em> in CFB mode with Twofish, key-128b, and iv-128b."} tf-cfb
  [0x91 0x08 0x06 0x8B 0x6E 0x52 0x09 0x43
   0x42 0x6C 0xB4 0x76 0x27 0x88 0xF2 0xD7
   0xE1 0x41 0xFA 0x63 0x2F 0x79 0x89 0x86
   0x93 0x6B 0xF6 0x5F 0xDE 0x19 0x63 0x7B
   0x63 0xDA 0xB8 0x58 0xB8 0x1C 0x2D 0xE3
   0x36 0x82 0xF8 0xDA 0xED 0xA0 0x5D 0xD0
   0xE1 0x2F 0x63 0x46 0xBC 0xFF 0x3A 0xA8
   0xB0 0xCD 0xB2 0xAA 0x57 0x13 0x5B 0xC7
   0x0F 0x51 0x82 0x00 0x97 0x1B 0x01 0xAA
   0x65 0xCE 0xDA 0x09 0x84 0xEE 0xC8 0x4F
   0xF4 0xD9 0x79 0x57 0x77 0x78 0xE2 0x0A
   0xD2 0xBC 0x48 0x68 0x2D 0x18 0xF4 0x87
   0x77 0xEF 0x36 0x5B 0x05 0x3E 0x91 0x24
   0x8E 0xB7 0x14 0x96 0x17 0x05 0x82 0x65
   0x4B 0x54 0xD7 0x00 0x1F 0xE6 0xC2 0x0A
   0x31 0xBF 0x2C 0xE9 0x80 0x45 0x9D 0x25
   0xC8 0xA6 0x06 0x81 0xCF 0x37 0x03 0xD4
   0x4A 0x01 0xA8 0x7A 0xC4 0x01 0x5C 0x99
   0x51 0x53 0xD5 0x3C 0xD4 0xEE 0x94 0x68
   0x42 0x71 0x55 0xF5 0xF7 0x78 0x63 0xA3
   0xD9 0x55 0x4F 0x56 0x93 0xF6 0x5F 0x9A
   0xDF 0x4D 0xBF 0x5F 0x25 0x0C 0x0F 0x40])

(def ^{:doc "A sample ciphertext message that is the result of encrypting
<em>pt-1</em> in OFB mode with Twofish, key-128b, and iv-128b."} tf-ofb
  [0x91 0x58 0x53 0x90 0x78 0x52 0xF4 0xD7
   0xD6 0x8A 0x6C 0x6F 0xF1 0x75 0x63 0x45
   0xF3 0x83 0x7B 0x5E 0xE0 0xF8 0xCE 0x88
   0x13 0xD6 0x31 0x43 0x48 0x69 0xE5 0x34
   0xF4 0xA4 0x71 0xFC 0x5E 0x4D 0xFE 0xBD
   0x4C 0xA3 0xED 0x09 0x22 0x55 0x64 0x4B
   0x8C 0xC4 0x36 0x70 0xC0 0xA9 0xC3 0x19
   0x19 0x65 0x7C 0xB0 0x05 0x50 0xD1 0x15
   0x59 0xD3 0x4E 0xEA 0x34 0x87 0xAE 0xCB
   0x96 0x5E 0x46 0x2A 0x99 0xBF 0x53 0x60
   0x81 0xEB 0x1D 0x0C 0x94 0x7A 0x2B 0x36
   0x63 0xE2 0xFC 0x48 0x02 0x85 0xFA 0x24
   0xF1 0x93 0xA0 0xA7 0x09 0x13 0xED 0xB7
   0x58 0x9D 0xE4 0xB1 0xBE 0x8D 0x84 0x65
   0xC7 0x82 0x80 0x74 0xCF 0x56 0x0F 0x4E
   0x30 0x64 0x55 0x0F 0x22 0x42 0x44 0x54
   0xEB 0xDC 0xA8 0xE3 0x74 0x48 0x1A 0x71
   0xF7 0x9A 0xBC 0xCD 0x85 0x0C 0x3F 0xFF
   0xB4 0x89 0x24 0x7C 0x74 0x32 0x9D 0xBC
   0x5B 0x44 0x0B 0x20 0x5A 0x81 0x59 0x2A
   0xE0 0xF8 0x2A 0x54 0x7F 0xA0 0xBE 0x55
   0xF3 0xE3 0x95 0xBE 0x76 0xCC 0x1B 0x8D])

(def ^{:doc "A sample ciphertext message that is the result of encrypting
<em>pt-1</em> in CTR mode with Twofish, key-128b, and iv-128b."} tf-ctr 
  [0xBD 0xA3 0xC8 0x66 0xDD 0x2F 0x0C 0xF2
   0x52 0x7E 0xE3 0xFA 0x13 0x44 0xFB 0xB0
   0xED 0x5D 0x5B 0x8A 0x8C 0x5B 0xBB 0x97
   0x61 0x66 0xDE 0x19 0xD2 0x40 0xF5 0xFB
   0x4E 0x15 0x23 0x5B 0x85 0x3A 0x96 0x14
   0xC0 0xAA 0xF8 0xE2 0x9D 0x68 0x61 0xE7
   0x75 0xAB 0x05 0xAD 0x02 0x2D 0xD9 0x58
   0xFE 0x12 0xAC 0xC3 0x73 0x2E 0xDB 0x3A
   0x15 0xCF 0x28 0x5E 0xDB 0xC4 0xD2 0x97
   0x5D 0x38 0x17 0xBA 0x22 0xC3 0xB7 0xCC
   0x10 0x5F 0xB8 0x27 0x34 0x66 0xBA 0x4C
   0x2B 0x1C 0x76 0xBF 0x9C 0x60 0x32 0xE7
   0x9A 0xA7 0x18 0x89 0xCB 0xE6 0xF6 0x23
   0xE7 0x0F 0xFD 0x6E 0xF4 0x0D 0x58 0x1C
   0xBB 0x1A 0xA4 0x68 0xD5 0xB0 0xA8 0x81
   0xC1 0x18 0x50 0x7E 0xD5 0xE7 0x16 0x79
   0xFA 0xFF 0x69 0xAA 0x06 0x77 0x8E 0x6F
   0x37 0xD7 0xE4 0x00 0xCE 0x95 0x7C 0xB8
   0x9A 0x82 0xC2 0xD4 0xAF 0x81 0xF8 0x3E
   0xB9 0x2C 0x20 0xD3 0x89 0x17 0xA3 0xA0
   0x6C 0xF9 0x36 0xE6 0x04 0x5E 0x9D 0x07
   0xAD 0x7C 0x50 0xB3 0x21 0x74 0x10 0x48])
