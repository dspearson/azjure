(ns azjure.cipher.aes
  "AES Cipher

  Implemented to meet the spec at
  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.libbyte :refer [bytes-word word-bytes]]))

(def ^{:private true
       :doc     "Vector of valid key sizes in bits"}
  key-sizes [128 192 256])

(def ^{:private true
       :doc     "Block size in bits"}
  block-size 128)

(def ^{:private true
       :doc     "Substitution box as a vector of 256 bytes.

  Use (nth sbox (bit-and n 0xff)) to look up the substition value for n, where n
  is a byte."}
  sbox [0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5
        0x30 0x01 0x67 0x2b 0xfe 0xd7 0xab 0x76
        0xca 0x82 0xc9 0x7d 0xfa 0x59 0x47 0xf0
        0xad 0xd4 0xa2 0xaf 0x9c 0xa4 0x72 0xc0
        0xb7 0xfd 0x93 0x26 0x36 0x3f 0xf7 0xcc
        0x34 0xa5 0xe5 0xf1 0x71 0xd8 0x31 0x15
        0x04 0xc7 0x23 0xc3 0x18 0x96 0x05 0x9a
        0x07 0x12 0x80 0xe2 0xeb 0x27 0xb2 0x75
        0x09 0x83 0x2c 0x1a 0x1b 0x6e 0x5a 0xa0
        0x52 0x3b 0xd6 0xb3 0x29 0xe3 0x2f 0x84
        0x53 0xd1 0x00 0xed 0x20 0xfc 0xb1 0x5b
        0x6a 0xcb 0xbe 0x39 0x4a 0x4c 0x58 0xcf
        0xd0 0xef 0xaa 0xfb 0x43 0x4d 0x33 0x85
        0x45 0xf9 0x02 0x7f 0x50 0x3c 0x9f 0xa8
        0x51 0xa3 0x40 0x8f 0x92 0x9d 0x38 0xf5
        0xbc 0xb6 0xda 0x21 0x10 0xff 0xf3 0xd2
        0xcd 0x0c 0x13 0xec 0x5f 0x97 0x44 0x17
        0xc4 0xa7 0x7e 0x3d 0x64 0x5d 0x19 0x73
        0x60 0x81 0x4f 0xdc 0x22 0x2a 0x90 0x88
        0x46 0xee 0xb8 0x14 0xde 0x5e 0x0b 0xdb
        0xe0 0x32 0x3a 0x0a 0x49 0x06 0x24 0x5c
        0xc2 0xd3 0xac 0x62 0x91 0x95 0xe4 0x79
        0xe7 0xc8 0x37 0x6d 0x8d 0xd5 0x4e 0xa9
        0x6c 0x56 0xf4 0xea 0x65 0x7a 0xae 0x08
        0xba 0x78 0x25 0x2e 0x1c 0xa6 0xb4 0xc6
        0xe8 0xdd 0x74 0x1f 0x4b 0xbd 0x8b 0x8a
        0x70 0x3e 0xb5 0x66 0x48 0x03 0xf6 0x0e
        0x61 0x35 0x57 0xb9 0x86 0xc1 0x1d 0x9e
        0xe1 0xf8 0x98 0x11 0x69 0xd9 0x8e 0x94
        0x9b 0x1e 0x87 0xe9 0xce 0x55 0x28 0xdf
        0x8c 0xa1 0x89 0x0d 0xbf 0xe6 0x42 0x68
        0x41 0x99 0x2d 0x0f 0xb0 0x54 0xbb 0x16])

(def ^{:private true
       :doc     "Substitution box as a vector of 256 bytes.

  Use (nth invsbox (bit-and n 0xff)) to look up the substition value for n,
  where n is a byte."}
  invsbox [0x52 0x09 0x6a 0xd5 0x30 0x36 0xa5 0x38
           0xbf 0x40 0xa3 0x9e 0x81 0xf3 0xd7 0xfb
           0x7c 0xe3 0x39 0x82 0x9b 0x2f 0xff 0x87
           0x34 0x8e 0x43 0x44 0xc4 0xde 0xe9 0xcb
           0x54 0x7b 0x94 0x32 0xa6 0xc2 0x23 0x3d
           0xee 0x4c 0x95 0x0b 0x42 0xfa 0xc3 0x4e
           0x08 0x2e 0xa1 0x66 0x28 0xd9 0x24 0xb2
           0x76 0x5b 0xa2 0x49 0x6d 0x8b 0xd1 0x25
           0x72 0xf8 0xf6 0x64 0x86 0x68 0x98 0x16
           0xd4 0xa4 0x5c 0xcc 0x5d 0x65 0xb6 0x92
           0x6c 0x70 0x48 0x50 0xfd 0xed 0xb9 0xda
           0x5e 0x15 0x46 0x57 0xa7 0x8d 0x9d 0x84
           0x90 0xd8 0xab 0x00 0x8c 0xbc 0xd3 0x0a
           0xf7 0xe4 0x58 0x05 0xb8 0xb3 0x45 0x06
           0xd0 0x2c 0x1e 0x8f 0xca 0x3f 0x0f 0x02
           0xc1 0xaf 0xbd 0x03 0x01 0x13 0x8a 0x6b
           0x3a 0x91 0x11 0x41 0x4f 0x67 0xdc 0xea
           0x97 0xf2 0xcf 0xce 0xf0 0xb4 0xe6 0x73
           0x96 0xac 0x74 0x22 0xe7 0xad 0x35 0x85
           0xe2 0xf9 0x37 0xe8 0x1c 0x75 0xdf 0x6e
           0x47 0xf1 0x1a 0x71 0x1d 0x29 0xc5 0x89
           0x6f 0xb7 0x62 0x0e 0xaa 0x18 0xbe 0x1b
           0xfc 0x56 0x3e 0x4b 0xc6 0xd2 0x79 0x20
           0x9a 0xdb 0xc0 0xfe 0x78 0xcd 0x5a 0xf4
           0x1f 0xdd 0xa8 0x33 0x88 0x07 0xc7 0x31
           0xb1 0x12 0x10 0x59 0x27 0x80 0xec 0x5f
           0x60 0x51 0x7f 0xa9 0x19 0xb5 0x4a 0x0d
           0x2d 0xe5 0x7a 0x9f 0x93 0xc9 0x9c 0xef
           0xa0 0xe0 0x3b 0x4d 0xae 0x2a 0xf5 0xb0
           0xc8 0xeb 0xbb 0x3c 0x83 0x53 0x99 0x61
           0x17 0x2b 0x04 0x7e 0xba 0x77 0xd6 0x26
           0xe1 0x69 0x14 0x63 0x55 0x21 0x0c 0x7d])

(def ^{:private true
       :doc     "The round constant word array"}
  rcon [0x00000000 0x01000000 0x02000000 0x04000000
        0x08000000 0x10000000 0x20000000 0x40000000
        0x80000000 0x1b000000 0x36000000 0x6c000000
        0xd8000000 0xab000000 0x4d000000 0x9a000000
        0x2f000000 0x5e000000 0xbc000000 0x63000000
        0xc6000000 0x97000000 0x35000000 0x6a000000
        0xd4000000 0xb3000000 0x7d000000 0xfa000000
        0xef000000 0xc5000000 0x91000000])

(def ^{:private true
       :doc     "Fixed field multiplication table for multiplication by 2 in
  GF(256)"}
  x2gf256 [0x00 0x02 0x04 0x06 0x08 0x0a 0x0c 0x0e
           0x10 0x12 0x14 0x16 0x18 0x1a 0x1c 0x1e
           0x20 0x22 0x24 0x26 0x28 0x2a 0x2c 0x2e
           0x30 0x32 0x34 0x36 0x38 0x3a 0x3c 0x3e
           0x40 0x42 0x44 0x46 0x48 0x4a 0x4c 0x4e
           0x50 0x52 0x54 0x56 0x58 0x5a 0x5c 0x5e
           0x60 0x62 0x64 0x66 0x68 0x6a 0x6c 0x6e
           0x70 0x72 0x74 0x76 0x78 0x7a 0x7c 0x7e
           0x80 0x82 0x84 0x86 0x88 0x8a 0x8c 0x8e
           0x90 0x92 0x94 0x96 0x98 0x9a 0x9c 0x9e
           0xa0 0xa2 0xa4 0xa6 0xa8 0xaa 0xac 0xae
           0xb0 0xb2 0xb4 0xb6 0xb8 0xba 0xbc 0xbe
           0xc0 0xc2 0xc4 0xc6 0xc8 0xca 0xcc 0xce
           0xd0 0xd2 0xd4 0xd6 0xd8 0xda 0xdc 0xde
           0xe0 0xe2 0xe4 0xe6 0xe8 0xea 0xec 0xee
           0xf0 0xf2 0xf4 0xf6 0xf8 0xfa 0xfc 0xfe
           0x1b 0x19 0x1f 0x1d 0x13 0x11 0x17 0x15
           0x0b 0x09 0x0f 0x0d 0x03 0x01 0x07 0x05
           0x3b 0x39 0x3f 0x3d 0x33 0x31 0x37 0x35
           0x2b 0x29 0x2f 0x2d 0x23 0x21 0x27 0x25
           0x5b 0x59 0x5f 0x5d 0x53 0x51 0x57 0x55
           0x4b 0x49 0x4f 0x4d 0x43 0x41 0x47 0x45
           0x7b 0x79 0x7f 0x7d 0x73 0x71 0x77 0x75
           0x6b 0x69 0x6f 0x6d 0x63 0x61 0x67 0x65
           0x9b 0x99 0x9f 0x9d 0x93 0x91 0x97 0x95
           0x8b 0x89 0x8f 0x8d 0x83 0x81 0x87 0x85
           0xbb 0xb9 0xbf 0xbd 0xb3 0xb1 0xb7 0xb5
           0xab 0xa9 0xaf 0xad 0xa3 0xa1 0xa7 0xa5
           0xdb 0xd9 0xdf 0xdd 0xd3 0xd1 0xd7 0xd5
           0xcb 0xc9 0xcf 0xcd 0xc3 0xc1 0xc7 0xc5
           0xfb 0xf9 0xff 0xfd 0xf3 0xf1 0xf7 0xf5
           0xeb 0xe9 0xef 0xed 0xe3 0xe1 0xe7 0xe5])

(def ^{:private true
       :doc     "Fixed field multiplication table for multiplication by 3 in
  GF(256)"}
  x3gf256 [0x00 0x03 0x06 0x05 0x0c 0x0f 0x0a 0x09
           0x18 0x1b 0x1e 0x1d 0x14 0x17 0x12 0x11
           0x30 0x33 0x36 0x35 0x3c 0x3f 0x3a 0x39
           0x28 0x2b 0x2e 0x2d 0x24 0x27 0x22 0x21
           0x60 0x63 0x66 0x65 0x6c 0x6f 0x6a 0x69
           0x78 0x7b 0x7e 0x7d 0x74 0x77 0x72 0x71
           0x50 0x53 0x56 0x55 0x5c 0x5f 0x5a 0x59
           0x48 0x4b 0x4e 0x4d 0x44 0x47 0x42 0x41
           0xc0 0xc3 0xc6 0xc5 0xcc 0xcf 0xca 0xc9
           0xd8 0xdb 0xde 0xdd 0xd4 0xd7 0xd2 0xd1
           0xf0 0xf3 0xf6 0xf5 0xfc 0xff 0xfa 0xf9
           0xe8 0xeb 0xee 0xed 0xe4 0xe7 0xe2 0xe1
           0xa0 0xa3 0xa6 0xa5 0xac 0xaf 0xaa 0xa9
           0xb8 0xbb 0xbe 0xbd 0xb4 0xb7 0xb2 0xb1
           0x90 0x93 0x96 0x95 0x9c 0x9f 0x9a 0x99
           0x88 0x8b 0x8e 0x8d 0x84 0x87 0x82 0x81
           0x9b 0x98 0x9d 0x9e 0x97 0x94 0x91 0x92
           0x83 0x80 0x85 0x86 0x8f 0x8c 0x89 0x8a
           0xab 0xa8 0xad 0xae 0xa7 0xa4 0xa1 0xa2
           0xb3 0xb0 0xb5 0xb6 0xbf 0xbc 0xb9 0xba
           0xfb 0xf8 0xfd 0xfe 0xf7 0xf4 0xf1 0xf2
           0xe3 0xe0 0xe5 0xe6 0xef 0xec 0xe9 0xea
           0xcb 0xc8 0xcd 0xce 0xc7 0xc4 0xc1 0xc2
           0xd3 0xd0 0xd5 0xd6 0xdf 0xdc 0xd9 0xda
           0x5b 0x58 0x5d 0x5e 0x57 0x54 0x51 0x52
           0x43 0x40 0x45 0x46 0x4f 0x4c 0x49 0x4a
           0x6b 0x68 0x6d 0x6e 0x67 0x64 0x61 0x62
           0x73 0x70 0x75 0x76 0x7f 0x7c 0x79 0x7a
           0x3b 0x38 0x3d 0x3e 0x37 0x34 0x31 0x32
           0x23 0x20 0x25 0x26 0x2f 0x2c 0x29 0x2a
           0x0b 0x08 0x0d 0x0e 0x07 0x04 0x01 0x02
           0x13 0x10 0x15 0x16 0x1f 0x1c 0x19 0x1a])

(def ^{:private true
       :doc     "Fixed field multiplication table for multiplication by 9 in
  GF(256)"}
  x9gf256 [0x00 0x09 0x12 0x1b 0x24 0x2d 0x36 0x3f
           0x48 0x41 0x5a 0x53 0x6c 0x65 0x7e 0x77
           0x90 0x99 0x82 0x8b 0xb4 0xbd 0xa6 0xaf
           0xd8 0xd1 0xca 0xc3 0xfc 0xf5 0xee 0xe7
           0x3b 0x32 0x29 0x20 0x1f 0x16 0x0d 0x04
           0x73 0x7a 0x61 0x68 0x57 0x5e 0x45 0x4c
           0xab 0xa2 0xb9 0xb0 0x8f 0x86 0x9d 0x94
           0xe3 0xea 0xf1 0xf8 0xc7 0xce 0xd5 0xdc
           0x76 0x7f 0x64 0x6d 0x52 0x5b 0x40 0x49
           0x3e 0x37 0x2c 0x25 0x1a 0x13 0x08 0x01
           0xe6 0xef 0xf4 0xfd 0xc2 0xcb 0xd0 0xd9
           0xae 0xa7 0xbc 0xb5 0x8a 0x83 0x98 0x91
           0x4d 0x44 0x5f 0x56 0x69 0x60 0x7b 0x72
           0x05 0x0c 0x17 0x1e 0x21 0x28 0x33 0x3a
           0xdd 0xd4 0xcf 0xc6 0xf9 0xf0 0xeb 0xe2
           0x95 0x9c 0x87 0x8e 0xb1 0xb8 0xa3 0xaa
           0xec 0xe5 0xfe 0xf7 0xc8 0xc1 0xda 0xd3
           0xa4 0xad 0xb6 0xbf 0x80 0x89 0x92 0x9b
           0x7c 0x75 0x6e 0x67 0x58 0x51 0x4a 0x43
           0x34 0x3d 0x26 0x2f 0x10 0x19 0x02 0x0b
           0xd7 0xde 0xc5 0xcc 0xf3 0xfa 0xe1 0xe8
           0x9f 0x96 0x8d 0x84 0xbb 0xb2 0xa9 0xa0
           0x47 0x4e 0x55 0x5c 0x63 0x6a 0x71 0x78
           0x0f 0x06 0x1d 0x14 0x2b 0x22 0x39 0x30
           0x9a 0x93 0x88 0x81 0xbe 0xb7 0xac 0xa5
           0xd2 0xdb 0xc0 0xc9 0xf6 0xff 0xe4 0xed
           0x0a 0x03 0x18 0x11 0x2e 0x27 0x3c 0x35
           0x42 0x4b 0x50 0x59 0x66 0x6f 0x74 0x7d
           0xa1 0xa8 0xb3 0xba 0x85 0x8c 0x97 0x9e
           0xe9 0xe0 0xfb 0xf2 0xcd 0xc4 0xdf 0xd6
           0x31 0x38 0x23 0x2a 0x15 0x1c 0x07 0x0e
           0x79 0x70 0x6b 0x62 0x5d 0x54 0x4f 0x46])

(def ^{:private true
       :doc     "Fixed field multiplication table for multiplication by 11 in
  GF(256)"}
  x11gf256 [0x00 0x0b 0x16 0x1d 0x2c 0x27 0x3a 0x31
            0x58 0x53 0x4e 0x45 0x74 0x7f 0x62 0x69
            0xb0 0xbb 0xa6 0xad 0x9c 0x97 0x8a 0x81
            0xe8 0xe3 0xfe 0xf5 0xc4 0xcf 0xd2 0xd9
            0x7b 0x70 0x6d 0x66 0x57 0x5c 0x41 0x4a
            0x23 0x28 0x35 0x3e 0x0f 0x04 0x19 0x12
            0xcb 0xc0 0xdd 0xd6 0xe7 0xec 0xf1 0xfa
            0x93 0x98 0x85 0x8e 0xbf 0xb4 0xa9 0xa2
            0xf6 0xfd 0xe0 0xeb 0xda 0xd1 0xcc 0xc7
            0xae 0xa5 0xb8 0xb3 0x82 0x89 0x94 0x9f
            0x46 0x4d 0x50 0x5b 0x6a 0x61 0x7c 0x77
            0x1e 0x15 0x08 0x03 0x32 0x39 0x24 0x2f
            0x8d 0x86 0x9b 0x90 0xa1 0xaa 0xb7 0xbc
            0xd5 0xde 0xc3 0xc8 0xf9 0xf2 0xef 0xe4
            0x3d 0x36 0x2b 0x20 0x11 0x1a 0x07 0x0c
            0x65 0x6e 0x73 0x78 0x49 0x42 0x5f 0x54
            0xf7 0xfc 0xe1 0xea 0xdb 0xd0 0xcd 0xc6
            0xaf 0xa4 0xb9 0xb2 0x83 0x88 0x95 0x9e
            0x47 0x4c 0x51 0x5a 0x6b 0x60 0x7d 0x76
            0x1f 0x14 0x09 0x02 0x33 0x38 0x25 0x2e
            0x8c 0x87 0x9a 0x91 0xa0 0xab 0xb6 0xbd
            0xd4 0xdf 0xc2 0xc9 0xf8 0xf3 0xee 0xe5
            0x3c 0x37 0x2a 0x21 0x10 0x1b 0x06 0x0d
            0x64 0x6f 0x72 0x79 0x48 0x43 0x5e 0x55
            0x01 0x0a 0x17 0x1c 0x2d 0x26 0x3b 0x30
            0x59 0x52 0x4f 0x44 0x75 0x7e 0x63 0x68
            0xb1 0xba 0xa7 0xac 0x9d 0x96 0x8b 0x80
            0xe9 0xe2 0xff 0xf4 0xc5 0xce 0xd3 0xd8
            0x7a 0x71 0x6c 0x67 0x56 0x5d 0x40 0x4b
            0x22 0x29 0x34 0x3f 0x0e 0x05 0x18 0x13
            0xca 0xc1 0xdc 0xd7 0xe6 0xed 0xf0 0xfb
            0x92 0x99 0x84 0x8f 0xbe 0xb5 0xa8 0xa3])

(def ^{:private true
       :doc     "Fixed field multiplication table for multiplication by 13 in
  GF(256)"}
  x13gf256 [0x00 0x0d 0x1a 0x17 0x34 0x39 0x2e 0x23
            0x68 0x65 0x72 0x7f 0x5c 0x51 0x46 0x4b
            0xd0 0xdd 0xca 0xc7 0xe4 0xe9 0xfe 0xf3
            0xb8 0xb5 0xa2 0xaf 0x8c 0x81 0x96 0x9b
            0xbb 0xb6 0xa1 0xac 0x8f 0x82 0x95 0x98
            0xd3 0xde 0xc9 0xc4 0xe7 0xea 0xfd 0xf0
            0x6b 0x66 0x71 0x7c 0x5f 0x52 0x45 0x48
            0x03 0x0e 0x19 0x14 0x37 0x3a 0x2d 0x20
            0x6d 0x60 0x77 0x7a 0x59 0x54 0x43 0x4e
            0x05 0x08 0x1f 0x12 0x31 0x3c 0x2b 0x26
            0xbd 0xb0 0xa7 0xaa 0x89 0x84 0x93 0x9e
            0xd5 0xd8 0xcf 0xc2 0xe1 0xec 0xfb 0xf6
            0xd6 0xdb 0xcc 0xc1 0xe2 0xef 0xf8 0xf5
            0xbe 0xb3 0xa4 0xa9 0x8a 0x87 0x90 0x9d
            0x06 0x0b 0x1c 0x11 0x32 0x3f 0x28 0x25
            0x6e 0x63 0x74 0x79 0x5a 0x57 0x40 0x4d
            0xda 0xd7 0xc0 0xcd 0xee 0xe3 0xf4 0xf9
            0xb2 0xbf 0xa8 0xa5 0x86 0x8b 0x9c 0x91
            0x0a 0x07 0x10 0x1d 0x3e 0x33 0x24 0x29
            0x62 0x6f 0x78 0x75 0x56 0x5b 0x4c 0x41
            0x61 0x6c 0x7b 0x76 0x55 0x58 0x4f 0x42
            0x09 0x04 0x13 0x1e 0x3d 0x30 0x27 0x2a
            0xb1 0xbc 0xab 0xa6 0x85 0x88 0x9f 0x92
            0xd9 0xd4 0xc3 0xce 0xed 0xe0 0xf7 0xfa
            0xb7 0xba 0xad 0xa0 0x83 0x8e 0x99 0x94
            0xdf 0xd2 0xc5 0xc8 0xeb 0xe6 0xf1 0xfc
            0x67 0x6a 0x7d 0x70 0x53 0x5e 0x49 0x44
            0x0f 0x02 0x15 0x18 0x3b 0x36 0x21 0x2c
            0x0c 0x01 0x16 0x1b 0x38 0x35 0x22 0x2f
            0x64 0x69 0x7e 0x73 0x50 0x5d 0x4a 0x47
            0xdc 0xd1 0xc6 0xcb 0xe8 0xe5 0xf2 0xff
            0xb4 0xb9 0xae 0xa3 0x80 0x8d 0x9a 0x97])

(def ^{:private true
       :doc     "Fixed field multiplication table for multiplication by 14 in
  GF(256)"}
  x14gf256 [0x00 0x0e 0x1c 0x12 0x38 0x36 0x24 0x2a
            0x70 0x7e 0x6c 0x62 0x48 0x46 0x54 0x5a
            0xe0 0xee 0xfc 0xf2 0xd8 0xd6 0xc4 0xca
            0x90 0x9e 0x8c 0x82 0xa8 0xa6 0xb4 0xba
            0xdb 0xd5 0xc7 0xc9 0xe3 0xed 0xff 0xf1
            0xab 0xa5 0xb7 0xb9 0x93 0x9d 0x8f 0x81
            0x3b 0x35 0x27 0x29 0x03 0x0d 0x1f 0x11
            0x4b 0x45 0x57 0x59 0x73 0x7d 0x6f 0x61
            0xad 0xa3 0xb1 0xbf 0x95 0x9b 0x89 0x87
            0xdd 0xd3 0xc1 0xcf 0xe5 0xeb 0xf9 0xf7
            0x4d 0x43 0x51 0x5f 0x75 0x7b 0x69 0x67
            0x3d 0x33 0x21 0x2f 0x05 0x0b 0x19 0x17
            0x76 0x78 0x6a 0x64 0x4e 0x40 0x52 0x5c
            0x06 0x08 0x1a 0x14 0x3e 0x30 0x22 0x2c
            0x96 0x98 0x8a 0x84 0xae 0xa0 0xb2 0xbc
            0xe6 0xe8 0xfa 0xf4 0xde 0xd0 0xc2 0xcc
            0x41 0x4f 0x5d 0x53 0x79 0x77 0x65 0x6b
            0x31 0x3f 0x2d 0x23 0x09 0x07 0x15 0x1b
            0xa1 0xaf 0xbd 0xb3 0x99 0x97 0x85 0x8b
            0xd1 0xdf 0xcd 0xc3 0xe9 0xe7 0xf5 0xfb
            0x9a 0x94 0x86 0x88 0xa2 0xac 0xbe 0xb0
            0xea 0xe4 0xf6 0xf8 0xd2 0xdc 0xce 0xc0
            0x7a 0x74 0x66 0x68 0x42 0x4c 0x5e 0x50
            0x0a 0x04 0x16 0x18 0x32 0x3c 0x2e 0x20
            0xec 0xe2 0xf0 0xfe 0xd4 0xda 0xc8 0xc6
            0x9c 0x92 0x80 0x8e 0xa4 0xaa 0xb8 0xb6
            0x0c 0x02 0x10 0x1e 0x34 0x3a 0x28 0x26
            0x7c 0x72 0x60 0x6e 0x44 0x4a 0x58 0x56
            0x37 0x39 0x2b 0x25 0x0f 0x01 0x13 0x1d
            0x47 0x49 0x5b 0x55 0x7f 0x71 0x63 0x6d
            0xd7 0xd9 0xcb 0xc5 0xef 0xe1 0xf3 0xfd
            0xa7 0xa9 0xbb 0xb5 0x9f 0x91 0x83 0x8d])

(defn- maskfn
  "Calculates the word length mask (4-bytes) for a given shift value s."
  [s]
  (bit-and (bit-shift-left 0xFFFFFFFF s) 0xFFFFFFFF))

(def ^{:private  true
       :doc      "Memoization of the maskfn function"
       :arglists '([s])}
  mask (memoize maskfn))

(defn- rotate-word
  "Rotate a word with the given left and right shift.

  * If *lshift* is larger, the word will be rotated left.
  * If *rshift* is larger, the word will be rotated right.
  * If either argument is 0, no shift will occur and the function will evaluate
  to the given word.

  Valid shift values are multiples of 8 from 0 to 32 inclusive."
  {:added "0.2.0"}
  [word lshift rshift]
  (if (or (zero? lshift) (zero? rshift))
    word
    (bit-or (bit-and (bit-shift-left word lshift) (mask lshift))
            (bit-shift-right (bit-and word (mask rshift)) rshift))))

(defn- mod-shiftfn
  "Shift mod 4 for word length shifting"
  [s]
  (mod s 4))

(def ^{:private true
       :doc     "Memoization of mod-shiftfn"}
  mod-shift (memoize mod-shiftfn))

(defn- shift-in-bitsfn
  "Converts a byte shift to bits."
  [shift]
  (* 8 shift))

(def ^{:private true
       :doc     "Memoization of shift-in-bitsfn"}
  shift-in-bits (memoize shift-in-bitsfn))

(defn- inv-shift-in-bitsfn
  "Inverse of shift-in-bits on a word"
  [s]
  (- 32 (shift-in-bits s)))

(def ^{:private true
       :doc     "Memoization of inv-shift-in-bitsfh"}
  inv-shift-in-bits (memoize inv-shift-in-bitsfn))

(defn- rotate-word-left
  "Rotates a 32-bit word left by s bytes, placing the leftmost byte(s) in the
  rightmost byte positions. Valid values for s are 1,2, or 3.

  (rotate-word-left 0x12ab1f3b 1) => 0xab1f3b12"
  [x s]
  (let [sft (mod-shift s)
        lshift (shift-in-bits sft)
        rshift (inv-shift-in-bits sft)]
    (rotate-word x lshift rshift)))

(defn- rotate-word-right
  "Rotates a 32-bit word right by x bytes, placing the rightmost byte(s) in the
  leftmost byte positions.  Valid values for s are 1,2, or 3.

  (rotate-word-right 0x12ab1f3b 1) => 0x3b12ab1f"
  [x s]
  (let [sft (mod-shift s)
        rshift (shift-in-bits sft)
        lshift (inv-shift-in-bits sft)]
    (rotate-word x lshift rshift)))

(defn- get-in-sbox
  "Get a byte value of the the sbox (normal or inverse).  The shift argument
  should be a multiple of 8.

  Evaluates to a function over the given sbox (sbox or invsbox)"
  [sbox]
  (fn [x s]
    (if (zero? s)
      (nth sbox (bit-and x 0xff))
      (bit-shift-left
        (nth sbox
             (bit-and (bit-shift-right x s) 0xff)) s))))

(defn- sub-word
  "Substitutes each byte in a word with a new byte from the sbox"
  [x]
  (apply bit-or (map #((get-in-sbox sbox) x %) (range 0 32 8))))

(defn- inv-sub-word
  "Substitues each byte in a word with a new byte from the invsbox."
  [x]
  (apply bit-or (map #((get-in-sbox invsbox) x %) (range 0 32 8))))

(defn- sub-bytes
  "Maps sub-word or inv-sub-word over the given word to substitue from the
  appropriate sbox all the bytes.  inv should be false for encryption S-box
  substitution, true for decryption inverse S-box substitution."
  [w inv]
  (map (if inv inv-sub-word sub-word) w))

(defn- get-last-nk
  "Get the last nk items from a vector."
  [v nk]
  (subvec v (- (count v) nk)))

(defn- next-word
  "Calculates the next word during key expansion.

  Get the head and tail elements from the nk
  length tail vector of the key expansion.
  If the current index mod nk is 0

  1. Rotate the tail word left.
  2. Lookup the substitution word from the Sbox.
  3. XOR with a value from rcon.
  4. XOR with the head word.

  If the key size is 8 and the current index mod nk is 4

  1. Lookup the substition word for tail in the sbox.
  2. XOR with the head word.

  Else, XOR tail and head

  Evalutates to a function over the given nk key length.
  The function takes the current state of the key expansion and
  the index of the next word to be calculated."
  [nk]
  (fn [v idx]
    (let [tailvec (get-last-nk v nk)
          tail (last tailvec)
          head (first tailvec)]
      (conj v
            (if (zero? (mod idx nk))
              (bit-xor
                (bit-xor
                  (sub-word (rotate-word-left tail 1))
                  (nth rcon (/ idx nk)))
                head)
              (if (and (> nk 6) (= (mod idx nk) 4))
                (bit-xor (sub-word tail) head)
                (bit-xor tail head)))))))

(defn- expand-keyfn
  "Expands a key of 128, 192, or 256 bits to a 44, 52, or 60 word key sequence
  vector."
  [key] {:pre [(vector? key)
               (or (= (count key) 4)
                   (= (count key) 6)
                   (= (count key) 8))]}
  (let [nb 4
        nk (count key)
        nr (+ nk 6)]
    (reduce (next-word nk) key (range nk (* nb (inc nr))))))

(def ^{:private true
       :doc     "Memoization of expand-keyfn"}
  expand-key (memoize expand-keyfn))

(defn- transpose
  "Transpose a vector of vectors."
  [matrix]
  (apply mapv vector matrix))

(defn- add-round-key
  "Performs finite field addition (XOR) between the state and key material."
  [state km]
  (map bit-xor state km))

(defn- to-matrix
  "Converts a vector of 4 words into a matrix of 4x4 byte vectors."
  [state]
  (mapv word-bytes state))

(defn- to-words
  "Converts a matrix of 4x4 byte vectors into a vector of 4 words."
  [matrix]
  (mapv bytes-word matrix))

(defn- shift-rows
  "Shift the last three rows in the state matrix by 1, 2, and 3 bytes left if
  encrypting, right if decrypting.

  1. Converts the state (a vector of columns) into a vector of rows.
  2. The rows are then shifted 0, 1, 2, or 3 bytes.
  3. The vector of rows is then converted back into a vector of columns."
  [state inv]
  (let [words (to-words (transpose (to-matrix state)))
        rotatefn (if inv rotate-word-right rotate-word-left)
        rotated (map rotatefn words (range 4))]
    (to-words (transpose (to-matrix rotated)))))

(defn- mix-column
  "The mix column algorithm.

  The output word is defined as follows:

  b0 = 2a0 + 3a1 + a2 + a3
  b1 = a0 + 2a1 + 3a2 + a3
  b2 = a0 + a1 + 2a2 + 3a3
  b3 = 3a0 + a1 + a2 + 2a3

  As this is finite field arithemetic, the addition is done via XOR and the
  multiplication is done via pre-calculated table lookups (see x9gf256 above
  for an example).

  Evaluates to a vector of 4 bytes."
  [x]
  (vector
    (bit-xor
      (nth x2gf256 (nth x 0))
      (nth x3gf256 (nth x 1))
      (nth x 2)
      (nth x 3))
    (bit-xor
      (nth x 0)
      (nth x2gf256 (nth x 1))
      (nth x3gf256 (nth x 2))
      (nth x 3))
    (bit-xor
      (nth x 0)
      (nth x 1)
      (nth x2gf256 (nth x 2))
      (nth x3gf256 (nth x 3)))
    (bit-xor
      (nth x3gf256 (nth x 0))
      (nth x 1)
      (nth x 2)
      (nth x2gf256 (nth x 3)))))

(defn- inv-mix-column
  "The inverse mix column algorithm.

  The output word is defined as follows:

  b0 = 14a0 + 11a1 + 13a2 + 9a3
  b1 = 9a0 + 14a1 + 11a2 + 13a3
  b2 = 13a0 + 9a1 + 14a2 + 11a3
  b3 = 11a0 + 13a1 + 9a2 + 14a3

  As this is finite field arithemetic, the addition is done via XOR and the
  multiplication is done via pre-calculated table lookups (see x9gf256 above
  for an example).

  Evaluates to a vector of 4 bytes."
  [x]
  (vector
    (bit-xor
      (nth x14gf256 (nth x 0))
      (nth x11gf256 (nth x 1))
      (nth x13gf256 (nth x 2))
      (nth x9gf256 (nth x 3)))
    (bit-xor
      (nth x9gf256 (nth x 0))
      (nth x14gf256 (nth x 1))
      (nth x11gf256 (nth x 2))
      (nth x13gf256 (nth x 3)))
    (bit-xor
      (nth x13gf256 (nth x 0))
      (nth x9gf256 (nth x 1))
      (nth x14gf256 (nth x 2))
      (nth x11gf256 (nth x 3)))
    (bit-xor
      (nth x11gf256 (nth x 0))
      (nth x13gf256 (nth x 1))
      (nth x9gf256 (nth x 2))
      (nth x14gf256 (nth x 3)))))

(defn- mix-columns
  "Applies the mix-column or inv-mix-column algorithm to each word in the state.

  If inv is false, mix-column is applied, otherwise inv-mix-column is applied."
  [state inv]
  (let [mixfn (if inv inv-mix-column mix-column)]
    (map bytes-word (map mixfn (map word-bytes state)))))

(defn- cipher
  "The AES encryption cipher.

  1. Get the lower and upper bounds for the key schedule.
  2. Grab the key material out of the key schedule.
  3. If the current round is 0

      > 1. Add the key material to the state.

  4. If the current round is less than nr

      > 1. Do S-box substitution on the state.
      > 2. Shift the state rows.
      > 3. Mix the state columns.
      > 4. Add the key material to the state.

  5. Else the current round is equal to nr

      > 1. Do S-box substitution on the state.
      > 2. Shift the state rows.
      > 3. Add the key material to the state.

   Evaluates to a function over the given key and number of rounds.

   The function takes the state and current round number."
  {:added "0.2.0"
   :doc-private true}
  [ks nr]
  (fn [state round]
    (let [next (inc round)
          lower (* round 4)
          upper (* next 4)
          km (subvec ks lower upper)]
      (if (zero? round)
        (add-round-key state km)
        (if (< round nr)
          (add-round-key
            (mix-columns
              (shift-rows
                (sub-bytes state false) false) false) km)
          (add-round-key
            (shift-rows
              (sub-bytes state false) false) km))))))

(defn- inverse-cipher
  "The AES decryption cipher

  1. Get the lower and upper bounds for the key schedule.
  2. Grab the key material out of the key schedule.
  3. If the current round is equal to nr:

      > 1. Add the key material to the state.

  4. If the current is greater than 0:

      > 1. Shift the state rows.
      > 2. Do S-box substitution on the state.
      > 3. Add the key material to the state.
      > 4. Mix the state columns.

  5. Else the current round is 0:
      > 1. Shift the state rows.
      > 2. Do S-box substitution on the state.
      > 3. Add the key material to the state.

  Evaluates to a function over the given key and number of rounds.

  The function takes the state and current round number."
  {:added "0.2.0"
   :doc-private true}
  [ks nr]
  (fn [state round]
    (let [next (inc round)
          lower (* round 4)
          upper (* next 4)
          km (subvec ks lower upper)]
      (if (= round nr)
        (add-round-key state km)
        (if (pos? round)
          (mix-columns
            (add-round-key
              (sub-bytes
                (shift-rows state true) true) km) true)
          (add-round-key
            (sub-bytes
              (shift-rows state true) true) km))))))

(defn- process-block
  "Process a vector of 16 byte values (one 128-bit block) for encryption or
  decryption.

  1. *block*: A vector of 16 byte values representing a block of 4 words.
  2. *key*: A 4, 6, or 8 word vector representing a 128, 192, or 256 bit key.
  3. *enc*: true if you are encrypting, false if you are decrypting.

  Evaluates to a vector of bytes."
  {:added "0.2.0"}
  [block {:keys [ks nk enc] :as m}]
  {:pre [(contains? m :ks)
         (contains? m :nk)
         (contains? m :enc)
         (vector? (:ks m))
         (or (= 44 (count (:ks m)))
             (= 52 (count (:ks m)))
             (= 60 (count (:ks m))))
         (pos? (:nk m))
         (or (= 4 (:nk m))
             (= 6 (:nk m))
             (= 8 (:nk m)))
         (= 16 (count block))]}
  (let [nr (+ nk 6)
        encfn (if enc cipher inverse-cipher)
        rv (if enc (range (inc nr)) (range nr -1 -1))
        block (mapv bytes-word (partition 4 block))]
    (->> (reduce (encfn ks nr) block rv)
         (vec)
         (mapv word-bytes)
         (reduce into))))

(defmethod initialize :aes [m]
  (let [key-words (mapv bytes-word (partition 4 (:key m)))]
    (assoc m :ks (expand-key key-words) :nk (count key-words))))

(defmethod keysizes-bits :aes [_] key-sizes)
(defmethod blocksize-bits :aes [_] block-size)
(defmethod encrypt-block :aes [m block]
  (process-block block (assoc m :enc true)))
(defmethod decrypt-block :aes [m block]
  (process-block block (assoc m :enc false)))