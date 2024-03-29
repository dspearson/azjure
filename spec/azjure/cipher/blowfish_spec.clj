(ns azjure.cipher.blowfish-spec
  (:require [azjure.libtest :refer :all]
            [speclj.core :refer :all]))

(def ct-64-bf-ecb-base
  [0x54 0x85 0x9A 0x6A 0x7E 0xD1 0x95 0x1F
   0x06 0xCB 0xE2 0xB0 0x40 0x78 0x4C 0x70
   0x7B 0x4D 0x8A 0xAE 0x12 0x59 0x4E 0x5C
   0x5A 0x05 0x79 0x27 0xE2 0x5B 0x22 0x66
   0x1C 0xE3 0x7A 0xDC 0xE3 0xCD 0xEA 0x26])

(def ct-64-bf-ecb-iso7186
  (into ct-64-bf-ecb-base [0x21 0x3F 0xF6 0xB9 0x24 0x2B 0x4F 0x58]))

(def ct-64-bf-ecb-x923
  (into ct-64-bf-ecb-base [0x2E 0x46 0x87 0x6D 0xF1 0xBE 0x52 0x12]))

(def ct-64-bf-ecb-pkcs7
  (into ct-64-bf-ecb-base [0x29 0x55 0x66 0x4A 0x0A 0x90 0x4E 0x1A]))

(def ct-64-bf-ecb-zero
  (into ct-64-bf-ecb-base [0x28 0xF0 0xBF 0x95 0x4E 0x77 0xFE 0xEC]))

(def ct-64-bf-cbc-base
  [0x54 0x85 0x9a 0x6a 0x7e 0xd1 0x95 0x1f
   0x0e 0xe7 0x35 0xf3 0x38 0x98 0x79 0xf4
   0x5b 0xd7 0xb1 0x5a 0x63 0x42 0x03 0x9b
   0xbd 0xe5 0xdf 0x82 0x43 0x78 0xa7 0x4f
   0xec 0x7c 0xff 0xae 0x47 0xa4 0x7a 0x50])

(def ct-64-bf-cbc-iso7186
  (into ct-64-bf-cbc-base [0xb1 0x91 0xad 0x63 0xf3 0x57 0x56 0x05]))

(def ct-64-bf-cbc-x923
  (into ct-64-bf-cbc-base [0x5e 0x98 0x6e 0x01 0x32 0xbb 0x9c 0xcb]))

(def ct-64-bf-cbc-pkcs7
  (into ct-64-bf-cbc-base [0xb5 0x1c 0x0a 0x93 0x43 0x7e 0x21 0xe6]))

(def ct-64-bf-cbc-zero
  (into ct-64-bf-cbc-base [0xf8 0xf8 0x4a 0x78 0xc8 0x47 0xc1 0x4f]))

(def ct-64-bf-pcbc-base
  [0x54 0x85 0x9a 0x6a 0x7e 0xd1 0x95 0x1f
   0xe7 0x7d 0x1f 0x62 0xc3 0x87 0x95 0x8d
   0xac 0xfe 0x75 0x38 0xe0 0xb9 0x3e 0x60
   0x55 0x76 0x42 0x89 0xcc 0x2b 0x71 0xf5
   0x05 0x3f 0xc8 0x01 0xe4 0xc5 0x98 0x6f])

(def ct-64-bf-pcbc-iso7186
  (into ct-64-bf-pcbc-base [0xdf 0x0b 0x35 0xa3 0xe0 0x7d 0x6b 0x4c]))

(def ct-64-bf-pcbc-x923
  (into ct-64-bf-pcbc-base [0xd1 0x1a 0xa6 0x26 0xd9 0x8f 0x89 0x22]))

(def ct-64-bf-pcbc-pkcs7
  (into ct-64-bf-pcbc-base [0x06 0x6d 0x21 0x3d 0x86 0x2e 0x14 0x1c]))

(def ct-64-bf-pcbc-zero
  (into ct-64-bf-pcbc-base [0xc7 0x07 0xac 0xe9 0x27 0x82 0x6d 0xf3]))

(def ct-64-bf-cfb-base
  [0x1a 0x91 0xf2 0x65 0x10 0xed 0xb4 0x1b
   0x83 0x4b 0x1b 0x6c 0x2d 0xfa 0x1f 0x35
   0xec 0xfd 0xdd 0xea 0x49 0x56 0x2e 0x82
   0xb0 0x85 0x2b 0x99 0x29 0x8e 0x37 0x99
   0x13 0xf4 0x92 0x59 0xeb 0x7d 0x0d 0xaa])

(def ct-64-bf-cfb-iso7186
  (into ct-64-bf-cfb-base [0x7f 0xb5 0x27 0x46 0x7b 0xeb 0x30 0x52]))

(def ct-64-bf-cfb-x923
  (into ct-64-bf-cfb-base [0x7f 0xb5 0x27 0x46 0xfb 0xeb 0x30 0x56]))

(def ct-64-bf-cfb-pkcs7
  (into ct-64-bf-cfb-base [0x7f 0xb5 0x27 0x46 0xff 0xef 0x34 0x56]))

(def ct-64-bf-cfb-zero
  (into ct-64-bf-cfb-base [0x7f 0xb5 0x27 0x46 0xfb 0xeb 0x30 0x52]))

(def ct-64-bf-ofb-base
  [0x1a 0x91 0xf2 0x65 0x10 0xed 0xb4 0x1b
   0x8a 0xe0 0x52 0x95 0x23 0x63 0xbc 0x41
   0x35 0x8c 0xca 0x85 0xc9 0xc9 0x44 0x0f
   0x40 0xe7 0xbe 0x72 0xb6 0x66 0xf0 0x0e
   0x7a 0xa2 0x0a 0xe4 0x97 0x1f 0x43 0xd1])

(def ct-64-bf-ofb-iso7186
  (into ct-64-bf-ofb-base [0x94 0x34 0x58 0xa8 0x81 0x95 0x48 0xab]))

(def ct-64-bf-ofb-x923
  (into ct-64-bf-ofb-base [0x94 0x34 0x58 0xa8 0x01 0x95 0x48 0xaf]))

(def ct-64-bf-ofb-pkcs7
  (into ct-64-bf-ofb-base [0x94 0x34 0x58 0xa8 0x05 0x91 0x4c 0xaf]))

(def ct-64-bf-ofb-zero
  (into ct-64-bf-ofb-base [0x94 0x34 0x58 0xa8 0x01 0x95 0x48 0xab]))

(def ct-64-bf-ctr-base
  [0x1a 0x91 0xf2 0x65 0x10 0xed 0xb4 0x1b
   0x0f 0xcd 0x64 0x25 0x38 0x26 0x71 0x87
   0xcb 0x0c 0x6e 0x4c 0xc7 0x8c 0xec 0x6e
   0x16 0x78 0x86 0xdb 0x65 0x7e 0x0c 0xd1
   0xd8 0x4d 0x96 0x08 0x43 0x76 0x89 0xcb])

(def ct-64-bf-ctr-iso7186
  (into ct-64-bf-ctr-base [0x4f 0x0a 0x72 0x9b 0x43 0x40 0x08 0xed]))

(def ct-64-bf-ctr-x923
  (into ct-64-bf-ctr-base [0x4f 0x0a 0x72 0x9b 0xc3 0x40 0x08 0xe9]))

(def ct-64-bf-ctr-pkcs7
  (into ct-64-bf-ctr-base [0x4f 0x0a 0x72 0x9b 0xc7 0x44 0x0c 0xe9]))

(def ct-64-bf-ctr-zero
  (into ct-64-bf-ctr-base [0x4f 0x0a 0x72 0x9b 0xc3 0x40 0x08 0xed]))

(def ^{:private true
       :doc     "Suite tests"}
  test-suites [[:ecb :iso7816 ct-64-bf-ecb-iso7186]
               [:ecb :iso10126 ct-64-bf-ecb-base]
               [:ecb :pkcs7 ct-64-bf-ecb-pkcs7]
               [:ecb :x923 ct-64-bf-ecb-x923]
               [:ecb :zero ct-64-bf-ecb-zero]
               [:cbc :iso7816 ct-64-bf-cbc-iso7186]
               [:cbc :iso10126 ct-64-bf-cbc-base]
               [:cbc :pkcs7 ct-64-bf-cbc-pkcs7]
               [:cbc :x923 ct-64-bf-cbc-x923]
               [:cbc :zero ct-64-bf-cbc-zero]
               [:pcbc :iso7816 ct-64-bf-pcbc-iso7186]
               [:pcbc :iso10126 ct-64-bf-pcbc-base]
               [:pcbc :pkcs7 ct-64-bf-pcbc-pkcs7]
               [:pcbc :x923 ct-64-bf-pcbc-x923]
               [:pcbc :zero ct-64-bf-pcbc-zero]
               [:cfb :iso7816 ct-64-bf-cfb-iso7186]
               [:cfb :iso10126 ct-64-bf-cfb-base]
               [:cfb :pkcs7 ct-64-bf-cfb-pkcs7]
               [:cfb :x923 ct-64-bf-cfb-x923]
               [:cfb :zero ct-64-bf-cfb-zero]
               [:ofb :iso7816 ct-64-bf-ofb-iso7186]
               [:ofb :iso10126 ct-64-bf-ofb-base]
               [:ofb :pkcs7 ct-64-bf-ofb-pkcs7]
               [:ofb :x923 ct-64-bf-ofb-x923]
               [:ofb :zero ct-64-bf-ofb-zero]
               [:ctr :iso7816 ct-64-bf-ctr-iso7186]
               [:ctr :iso10126 ct-64-bf-ctr-base]
               [:ctr :pkcs7 ct-64-bf-ctr-pkcs7]
               [:ctr :x923 ct-64-bf-ctr-x923]
               [:ctr :zero ct-64-bf-ctr-zero]])

(def ^{:private true
       :doc     "Test vectors as defined in the spec."}
  test-vectors [[[0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0x4E 0xF9 0x97 0x45 0x61 0x98 0xDD 0x78]]
                [[0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF]
                 [0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF]
                 [0x51 0x86 0x6F 0xD5 0xB8 0x5E 0xCB 0x8A]]
                [[0x30 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0x10 0x00 0x00 0x00 0x00 0x00 0x00 0x01]
                 [0x7D 0x85 0x6F 0x9A 0x61 0x30 0x63 0xF2]]
                [[0x11 0x11 0x11 0x11 0x11 0x11 0x11 0x11]
                 [0x11 0x11 0x11 0x11 0x11 0x11 0x11 0x11]
                 [0x24 0x66 0xDD 0x87 0x8B 0x96 0x3C 0x9D]]
                [[0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 [0x11 0x11 0x11 0x11 0x11 0x11 0x11 0x11]
                 [0x61 0xF9 0xC3 0x80 0x22 0x81 0xB0 0x96]]
                [[0x11 0x11 0x11 0x11 0x11 0x11 0x11 0x11]
                 [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 [0x7D 0x0C 0xC6 0x30 0xAF 0xDA 0x1E 0xC7]]
                [[0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0x4E 0xF9 0x97 0x45 0x61 0x98 0xDD 0x78]]
                [[0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10]
                 [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 [0x0A 0xCE 0xAB 0x0F 0xC6 0xA0 0xA2 0x8D]]
                [[0x7C 0xA1 0x10 0x45 0x4A 0x1A 0x6E 0x57]
                 [0x01 0xA1 0xD6 0xD0 0x39 0x77 0x67 0x42]
                 [0x59 0xC6 0x82 0x45 0xEB 0x05 0x28 0x2B]]
                [[0x01 0x31 0xD9 0x61 0x9D 0xC1 0x37 0x6E]
                 [0x5C 0xD5 0x4C 0xA8 0x3D 0xEF 0x57 0xDA]
                 [0xB1 0xB8 0xCC 0x0B 0x25 0x0F 0x09 0xA0]]
                [[0x07 0xA1 0x13 0x3E 0x4A 0x0B 0x26 0x86]
                 [0x02 0x48 0xD4 0x38 0x06 0xF6 0x71 0x72]
                 [0x17 0x30 0xE5 0x77 0x8B 0xEA 0x1D 0xA4]]
                [[0x38 0x49 0x67 0x4C 0x26 0x02 0x31 0x9E]
                 [0x51 0x45 0x4B 0x58 0x2D 0xDF 0x44 0x0A]
                 [0xA2 0x5E 0x78 0x56 0xCF 0x26 0x51 0xEB]]
                [[0x04 0xB9 0x15 0xBA 0x43 0xFE 0xB5 0xB6]
                 [0x42 0xFD 0x44 0x30 0x59 0x57 0x7F 0xA2]
                 [0x35 0x38 0x82 0xB1 0x09 0xCE 0x8F 0x1A]]
                [[0x01 0x13 0xB9 0x70 0xFD 0x34 0xF2 0xCE]
                 [0x05 0x9B 0x5E 0x08 0x51 0xCF 0x14 0x3A]
                 [0x48 0xF4 0xD0 0x88 0x4C 0x37 0x99 0x18]]
                [[0x01 0x70 0xF1 0x75 0x46 0x8F 0xB5 0xE6]
                 [0x07 0x56 0xD8 0xE0 0x77 0x47 0x61 0xD2]
                 [0x43 0x21 0x93 0xB7 0x89 0x51 0xFC 0x98]]
                [[0x43 0x29 0x7F 0xAD 0x38 0xE3 0x73 0xFE]
                 [0x76 0x25 0x14 0xB8 0x29 0xBF 0x48 0x6A]
                 [0x13 0xF0 0x41 0x54 0xD6 0x9D 0x1A 0xE5]]
                [[0x07 0xA7 0x13 0x70 0x45 0xDA 0x2A 0x16]
                 [0x3B 0xDD 0x11 0x90 0x49 0x37 0x28 0x02]
                 [0x2E 0xED 0xDA 0x93 0xFF 0xD3 0x9C 0x79]]
                [[0x04 0x68 0x91 0x04 0xC2 0xFD 0x3B 0x2F]
                 [0x26 0x95 0x5F 0x68 0x35 0xAF 0x60 0x9A]
                 [0xD8 0x87 0xE0 0x39 0x3C 0x2D 0xA6 0xE3]]
                [[0x37 0xD0 0x6B 0xB5 0x16 0xCB 0x75 0x46]
                 [0x16 0x4D 0x5E 0x40 0x4F 0x27 0x52 0x32]
                 [0x5F 0x99 0xD0 0x4F 0x5B 0x16 0x39 0x69]]
                [[0x1F 0x08 0x26 0x0D 0x1A 0xC2 0x46 0x5E]
                 [0x6B 0x05 0x6E 0x18 0x75 0x9F 0x5C 0xCA]
                 [0x4A 0x05 0x7A 0x3B 0x24 0xD3 0x97 0x7B]]
                [[0x58 0x40 0x23 0x64 0x1A 0xBA 0x61 0x76]
                 [0x00 0x4B 0xD6 0xEF 0x09 0x17 0x60 0x62]
                 [0x45 0x20 0x31 0xC1 0xE4 0xFA 0xDA 0x8E]]
                [[0x02 0x58 0x16 0x16 0x46 0x29 0xB0 0x07]
                 [0x48 0x0D 0x39 0x00 0x6E 0xE7 0x62 0xF2]
                 [0x75 0x55 0xAE 0x39 0xF5 0x9B 0x87 0xBD]]
                [[0x49 0x79 0x3E 0xBC 0x79 0xB3 0x25 0x8F]
                 [0x43 0x75 0x40 0xC8 0x69 0x8F 0x3C 0xFA]
                 [0x53 0xC5 0x5F 0x9C 0xB4 0x9F 0xC0 0x19]]
                [[0x4F 0xB0 0x5E 0x15 0x15 0xAB 0x73 0xA7]
                 [0x07 0x2D 0x43 0xA0 0x77 0x07 0x52 0x92]
                 [0x7A 0x8E 0x7B 0xFA 0x93 0x7E 0x89 0xA3]]
                [[0x49 0xE9 0x5D 0x6D 0x4C 0xA2 0x29 0xBF]
                 [0x02 0xFE 0x55 0x77 0x81 0x17 0xF1 0x2A]
                 [0xCF 0x9C 0x5D 0x7A 0x49 0x86 0xAD 0xB5]]
                [[0x01 0x83 0x10 0xDC 0x40 0x9B 0x26 0xD6]
                 [0x1D 0x9D 0x5C 0x50 0x18 0xF7 0x28 0xC2]
                 [0xD1 0xAB 0xB2 0x90 0x65 0x8B 0xC7 0x78]]
                [[0x1C 0x58 0x7F 0x1C 0x13 0x92 0x4F 0xEF]
                 [0x30 0x55 0x32 0x28 0x6D 0x6F 0x29 0x5A]
                 [0x55 0xCB 0x37 0x74 0xD1 0x3E 0xF2 0x01]]
                [[0x01 0x01 0x01 0x01 0x01 0x01 0x01 0x01]
                 [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 [0xFA 0x34 0xEC 0x48 0x47 0xB2 0x68 0xB2]]
                [[0x1F 0x1F 0x1F 0x1F 0x0E 0x0E 0x0E 0x0E]
                 [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 [0xA7 0x90 0x79 0x51 0x08 0xEA 0x3C 0xAE]]
                [[0xE0 0xFE 0xE0 0xFE 0xF1 0xFE 0xF1 0xFE]
                 [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 [0xC3 0x9E 0x07 0x2D 0x9F 0xAC 0x63 0x1D]]
                [[0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF]
                 [0x01 0x49 0x33 0xE0 0xCD 0xAF 0xF6 0xE4]]
                [[0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF]
                 [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0xF2 0x1E 0x9A 0x77 0xB7 0x1C 0x49 0xBC]]
                [[0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                 [0x24 0x59 0x46 0x88 0x57 0x54 0x36 0x9A]]
                [[0xFE 0xDC 0xBA 0x98 0x76 0x54 0x32 0x10]
                 [0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF]
                 [0x6B 0x5C 0x5A 0x9C 0x5D 0x9E 0x0A 0x5A]]])

(def ^{:private true
       :doc     "Configuration Map"}
  cm {:type :blowfish :eid :str :doe :str})

(describe
  "Blowfish"
  (check-blocksize cm 64)
  (check-keysizes cm (range 32 449))
  (check-test-vectors cm test-vectors)
  (check-test-suites cm test-suites :key zeros-64-bits :iv zeros-64-bits))

(comment
  "Pull the test vectors out of vectors.txt"
  (doseq [tuple (->> (slurp "https://www.schneier.com/code/vectors.txt")
                     (clojure.string/split-lines)
                     (drop-while #(not (.startsWith % "key bytes")))
                     (take-while #(not (.startsWith % "set_key")))
                     (rest)
                     (map #(clojure.string/split % #" +")))]
    (clojure.pprint (->> tuple
                         (mapv (partial partition 2))
                         (mapv (fn [x] (mapv #(conj % \x \0) x)))
                         (mapv #(mapv (partial apply str) %))))))