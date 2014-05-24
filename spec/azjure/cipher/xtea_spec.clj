(ns azjure.cipher.xtea-spec
  (:require [azjure.libtest :refer :all]
            [speclj.core :refer :all]))

(def ^{:doc "Base XTEA/ECB test ciphertext"}
  ct-64-xtea-ecb-base
  [0x36 0xfd 0x7b 0x16 0xb9 0x3e 0xfb 0xa7
   0x39 0x1f 0xc5 0x69 0x3e 0xca 0xc4 0x56
   0xb3 0xe1 0x57 0xd2 0xaa 0xbd 0x2b 0xfa
   0xe4 0x9e 0x62 0xe7 0x11 0xfe 0x41 0xfc
   0xcb 0x7f 0x7b 0x0e 0xea 0xb4 0x8b 0x5b])

(def ^{:doc "XTEA/ECB/X923 test ciphertext"}
  ct-64-xtea-ecb-x923
  (into ct-64-xtea-ecb-base [0xa0 0x80 0x0f 0x2c 0xee 0x86 0x07 0xea]))

(def ^{:doc "XTEA/ECB/ISO7816 test ciphertext"}
  ct-64-xtea-ecb-iso7816
  (into ct-64-xtea-ecb-base [0x76 0xe3 0xb2 0x10 0x25 0x02 0x50 0xd8]))

(def ^{:doc "XTEA/ECB/PKCS7 test ciphertext"}
  ct-64-xtea-ecb-pkcs7
  (into ct-64-xtea-ecb-base [0x9a 0xf5 0x58 0x7a 0x52 0x22 0xb4 0x24]))

(def ^{:doc "XTEA/ECB/ZERO test ciphertext"}
  ct-64-xtea-ecb-zero
  (into ct-64-xtea-ecb-base [0x9b 0x8f 0x57 0x31 0xb1 0xf9 0x9a 0x61]))

(def ^{:doc "Base XTEA/CBC test ciphertext"}
  ct-64-xtea-cbc-base
  [0x36 0xfd 0x7b 0x16 0xb9 0x3e 0xfb 0xa7
   0x9f 0x40 0xbf 0x59 0xa0 0x1d 0xcf 0x81
   0x42 0xa0 0x66 0x69 0x29 0x0a 0x0e 0x92
   0xb3 0x48 0xce 0x9f 0x41 0x52 0xa6 0xb9
   0x96 0x26 0x82 0x25 0x81 0xd2 0xae 0xfd])

(def ^{:doc "XTEA/CBC/X923 test ciphertext"}
  ct-64-xtea-cbc-x923
  (into ct-64-xtea-cbc-base [0x26 0xbe 0xe5 0xb8 0xf1 0x33 0xe0 0xf2]))

(def ^{:doc "XTEA/CBC/ISO7816 test ciphertext"}
  ct-64-xtea-cbc-iso7816
  (into ct-64-xtea-cbc-base [0x3a 0xee 0x99 0x51 0xb7 0x8c 0x3b 0xca]))

(def ^{:doc "XTEA/CBC/PKCS7 test ciphertext"}
  ct-64-xtea-cbc-pkcs7
  (into ct-64-xtea-cbc-base [0x25 0x0b 0x89 0x40 0x1b 0x6d 0xf5 0x99]))

(def ^{:doc "XTEA/CBC/ZERO test ciphertext"}
  ct-64-xtea-cbc-zero
  (into ct-64-xtea-cbc-base [0x5e 0x66 0xd2 0xb6 0x6d 0xdf 0x2e 0x5b]))

(def ^{:doc "Base XTEA/PCBC test ciphertext"}
  ct-64-xtea-pcbc-base
  [0x36 0xfd 0x7b 0x16 0xb9 0x3e 0xfb 0xa7
   0x0f 0x4a 0x86 0xb0 0x04 0xb9 0xd1 0x64
   0x4b 0x53 0x1b 0xdc 0xd3 0xd9 0x6d 0x91
   0xb6 0xc7 0x73 0xf3 0x4c 0xf7 0xf3 0x93
   0xfd 0xa4 0xd2 0x16 0x73 0x09 0xa5 0xd4])

(def ^{:doc "XTEA/PCBC/X923 test ciphertext"}
  ct-64-xtea-pcbc-x923
  (into ct-64-xtea-pcbc-base [0xf5 0xda 0xd3 0x77 0xbc 0x24 0xbd 0xa8]))

(def ^{:doc "XTEA/PCBC/ISO7816 test ciphertext"}
  ct-64-xtea-pcbc-iso7816
  (into ct-64-xtea-pcbc-base [0x25 0x98 0x4f 0xfa 0x20 0xb1 0x22 0xb5]))

(def ^{:doc "XTEA/PCBC/PKCS7 test ciphertext"}
  ct-64-xtea-pcbc-pkcs7
  (into ct-64-xtea-pcbc-base [0x37 0x6f 0xc8 0x18 0x07 0xf6 0x23 0x25]))

(def ^{:doc "XTEA/PCBC/ZERO test ciphertext"}
  ct-64-xtea-pcbc-zero
  (into ct-64-xtea-pcbc-base [0xfe 0x41 0xb8 0x53 0x79 0xfd 0x9b 0x64]))

(def ^{:doc "Base XTEA/CFB test ciphertext"}
  ct-64-xtea-cfb-base
  [0x8a 0x81 0xb1 0xf8 0x86 0x66 0x77 0xba
   0x53 0x91 0xd0 0xfd 0x51 0xf2 0xce 0xcd
   0x0f 0xa3 0x30 0x5b 0xba 0xd6 0xec 0x95
   0x3c 0xb2 0x91 0x17 0xcf 0xf8 0x0b 0x4e
   0x49 0xee 0x4d 0x37 0xa5 0xe0 0x08 0x1d])

(def ^{:doc "XTEA/CFB/X923 test ciphertext"}
  ct-64-xtea-cfb-x923
  (into ct-64-xtea-cfb-base [0x28 0x25 0x3c 0x3b 0xab 0x55 0xe8 0xb8]))

(def ^{:doc "XTEA/CFB/ISO7816 test ciphertext"}
  ct-64-xtea-cfb-iso7816
  (into ct-64-xtea-cfb-base [0x28 0x25 0x3c 0x3b 0x2b 0x55 0xe8 0xbc]))

(def ^{:doc "XTEA/CFB/PKCS7 test ciphertext"}
  ct-64-xtea-cfb-pkcs7
  (into ct-64-xtea-cfb-base [0x28 0x25 0x3c 0x3b 0xaf 0x51 0xec 0xb8]))

(def ^{:doc "XTEA/CFB/ZERO test ciphertext"}
  ct-64-xtea-cfb-zero
  (into ct-64-xtea-cfb-base [0x28 0x25 0x3c 0x3b 0xab 0x55 0xe8 0xbc]))

(def ^{:doc "Base XTEA/OFB test ciphertext"}
  ct-64-xtea-ofb-base
  [0x8a 0x81 0xb1 0xf8 0x86 0x66 0x77 0xba
   0xdb 0xc4 0x68 0x71 0x05 0xf2 0xbc 0xe4
   0x20 0x6d 0xae 0xc6 0x15 0x79 0x0d 0x47
   0x5d 0x7d 0x59 0xf7 0x60 0x0b 0x80 0xa1
   0x72 0x67 0x0b 0xbf 0x78 0xd0 0x1d 0x6d])

(def ^{:doc "XTEA/OFB/X923 test ciphertext"}
  ct-64-xtea-ofb-x923
  (into ct-64-xtea-ofb-base [0x15 0x5e 0x8e 0xb6 0xbd 0x81 0x60 0xb9]))

(def ^{:doc "XTEA/OFB/ISO7816 test ciphertext"}
  ct-64-xtea-ofb-iso7816
  (into ct-64-xtea-ofb-base [0x15 0x5e 0x8e 0xb6 0x3d 0x81 0x60 0xbd]))

(def ^{:doc "XTEA/OFB/PKCS7 test ciphertext"}
  ct-64-xtea-ofb-pkcs7
  (into ct-64-xtea-ofb-base [0x15 0x5e 0x8e 0xb6 0xb9 0x85 0x64 0xb9]))

(def ^{:doc "XTEA/OFB/ZERO test ciphertext"}
  ct-64-xtea-ofb-zero
  (into ct-64-xtea-ofb-base [0x15 0x5e 0x8e 0xb6 0xbd 0x81 0x60 0xbd]))

(def ^{:doc "Base XTEA/CTR test ciphertext"}
  ct-64-xtea-ctr-base
  [0x8a 0x81 0xb1 0xf8 0x86 0x66 0x77 0xba
   0x2c 0x38 0x06 0x1a 0xbe 0xa5 0x5a 0x1d
   0x3f 0xd4 0x8b 0x8b 0xbc 0x92 0xde 0x5f
   0x43 0x6c 0x33 0x53 0x32 0x6d 0xbb 0x21
   0x01 0x7f 0x1f 0x0a 0x01 0xd2 0x3f 0xf2])

(def ^{:doc "XTEA/CTR/X923 test ciphertext"}
  ct-64-xtea-ctr-x923
  (into ct-64-xtea-ctr-base [0x05 0x5e 0xf0 0x76 0x3d 0x71 0x20 0x68]))

(def ^{:doc "XTEA/CTR/ISO7816 test ciphertext"}
  ct-64-xtea-ctr-iso7816
  (into ct-64-xtea-ctr-base [0x05 0x5e 0xf0 0x76 0xbd 0x71 0x20 0x6c]))

(def ^{:doc "XTEA/CTR/PKCS7 test ciphertext"}
  ct-64-xtea-ctr-pkcs7
  (into ct-64-xtea-ctr-base [0x05 0x5e 0xf0 0x76 0x39 0x75 0x24 0x68]))

(def ^{:doc "XTEA/CTR/ZERO test ciphertext"}
  ct-64-xtea-ctr-zero
  (into ct-64-xtea-ctr-base [0x05 0x5e 0xf0 0x76 0x3d 0x71 0x20 0x6c]))

(def ^{:private true
       :doc     "Test vectors as defined in the spec."}
  test-vectors [[[0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                  0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0xde 0xe9 0xd4 0xd8 0xf7 0x13 0x1e 0xd9]]])

(def ^{:private true
       :doc     "Suite tests"}
  test-suites [[:ecb :iso7816 ct-64-xtea-ecb-iso7816]
               [:ecb :iso10126 ct-64-xtea-ecb-base]
               [:ecb :pkcs7 ct-64-xtea-ecb-pkcs7]
               [:ecb :x923 ct-64-xtea-ecb-x923]
               [:ecb :zero ct-64-xtea-ecb-zero]
               [:cbc :iso7816 ct-64-xtea-cbc-iso7816]
               [:cbc :iso10126 ct-64-xtea-cbc-base]
               [:cbc :pkcs7 ct-64-xtea-cbc-pkcs7]
               [:cbc :x923 ct-64-xtea-cbc-x923]
               [:cbc :zero ct-64-xtea-cbc-zero]
               [:pcbc :iso7816 ct-64-xtea-pcbc-iso7816]
               [:pcbc :iso10126 ct-64-xtea-pcbc-base]
               [:pcbc :pkcs7 ct-64-xtea-pcbc-pkcs7]
               [:pcbc :x923 ct-64-xtea-pcbc-x923]
               [:pcbc :zero ct-64-xtea-pcbc-zero]
               [:cfb :iso7816 ct-64-xtea-cfb-iso7816]
               [:cfb :iso10126 ct-64-xtea-cfb-base]
               [:cfb :pkcs7 ct-64-xtea-cfb-pkcs7]
               [:cfb :x923 ct-64-xtea-cfb-x923]
               [:cfb :zero ct-64-xtea-cfb-zero]
               [:ofb :iso7816 ct-64-xtea-ofb-iso7816]
               [:ofb :iso10126 ct-64-xtea-ofb-base]
               [:ofb :pkcs7 ct-64-xtea-ofb-pkcs7]
               [:ofb :x923 ct-64-xtea-ofb-x923]
               [:ofb :zero ct-64-xtea-ofb-zero]
               [:ctr :iso7816 ct-64-xtea-ctr-iso7816]
               [:ctr :iso10126 ct-64-xtea-ctr-base]
               [:ctr :pkcs7 ct-64-xtea-ctr-pkcs7]
               [:ctr :x923 ct-64-xtea-ctr-x923]
               [:ctr :zero ct-64-xtea-ctr-zero]])

(def ^{:private true
       :doc     "Configuration Map"}
  cm {:type :xtea :eid :str :doe :str})

(describe
  "XTEA"
  (check-blocksize cm 64)
  (check-keysizes cm [128])
  (check-test-vectors cm test-vectors)
  (check-test-suites cm test-suites :iv zeros-64-bits))