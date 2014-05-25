(ns azjure.cipher.salsa20-spec
  (:require [azjure.libtest :refer :all]
            [speclj.core :refer :all]))

(def ^{:private true
       :doc     "Test vectors as defined in the spec."}
  test-vectors [
                ; [[0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
                ;  0x0a 0xf7 0x56 0x47 0xf2 0x9f 0x61 0x5d]
                ; [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                ;  0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                ; [0xc8 0x42 0xa0 0x89 0x72 0xb4 0x3d 0x20
                ;  0x83 0x6c 0x91 0xd1 0xb7 0x53 0x0f 0x6b]]
                ;[[0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
                ;  0xbe 0xd0 0xac 0x83 0x94 0x0a 0xc2 0x98
                ;  0xba 0xc7 0x7a 0x77 0x17 0x94 0x28 0x63]
                ; [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                ;  0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                ; [0x1b 0x38 0x6c 0x02 0x10 0xdc 0xad 0xcb
                ;  0xdd 0x0e 0x41 0xaa 0x08 0xa7 0xa7 0xe8]]
                ;[[0x23 0x42 0xbb 0x9e 0xfa 0x38 0x54 0x2c
                ;  0xbe 0xd0 0xac 0x83 0x94 0x0a 0xc2 0x98
                ;  0x8d 0x7c 0x47 0xce 0x26 0x49 0x08 0x46
                ;  0x1c 0xc1 0xb5 0x13 0x7a 0xe6 0xb6 0x04]
                ; [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                ;  0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
                ; [0x4f 0x6a 0x20 0x38 0x28 0x68 0x97 0xb9
                ;  0xc9 0x87 0x01 0x36 0x55 0x33 0x17 0xfa]]
                ])

(def ^{:private true
       :doc     "Suite tests"}
  test-suites [
               ; [:ecb :iso7816 ct-128-cast6-ecb-iso7816]
               ;[:ecb :iso10126 ct-128-cast6-ecb-base]
               ;[:ecb :pkcs7 ct-128-cast6-ecb-pkcs7]
               ;[:ecb :x923 ct-128-cast6-ecb-x923]
               ;[:ecb :zero ct-128-cast6-ecb-zero]
               ;[:cbc :iso7816 ct-128-cast6-cbc-iso7816]
               ;[:cbc :iso10126 ct-128-cast6-cbc-base]
               ;[:cbc :pkcs7 ct-128-cast6-cbc-pkcs7]
               ;[:cbc :x923 ct-128-cast6-cbc-x923]
               ;[:cbc :zero ct-128-cast6-cbc-zero]
               ;[:pcbc :iso7816 ct-128-cast6-pcbc-iso7816]
               ;[:pcbc :iso10126 ct-128-cast6-pcbc-base]
               ;[:pcbc :pkcs7 ct-128-cast6-pcbc-pkcs7]
               ;[:pcbc :x923 ct-128-cast6-pcbc-x923]
               ;[:pcbc :zero ct-128-cast6-pcbc-zero]
               ;[:cfb :iso7816 ct-128-cast6-cfb-iso7816]
               ;[:cfb :iso10126 ct-128-cast6-cfb-base]
               ;[:cfb :pkcs7 ct-128-cast6-cfb-pkcs7]
               ;[:cfb :x923 ct-128-cast6-cfb-x923]
               ;[:cfb :zero ct-128-cast6-cfb-zero]
               ;[:ofb :iso7816 ct-128-cast6-ofb-iso7816]
               ;[:ofb :iso10126 ct-128-cast6-ofb-base]
               ;[:ofb :pkcs7 ct-128-cast6-ofb-pkcs7]
               ;[:ofb :x923 ct-128-cast6-ofb-x923]
               ;[:ofb :zero ct-128-cast6-ofb-zero]
               ;[:ctr :iso7816 ct-128-cast6-ctr-iso7816]
               ;[:ctr :iso10126 ct-128-cast6-ctr-base]
               ;[:ctr :pkcs7 ct-128-cast6-ctr-pkcs7]
               ;[:ctr :x923 ct-128-cast6-ctr-x923]
               ;[:ctr :zero ct-128-cast6-ctr-zero]
               ])

(def ^{:private true
       :doc     "Configuration Map"}
  cm {:type :salsa20 :eid :str :doe :str})

(describe
  "Salsa20"
  (check-keysizes cm [128 256])
  (check-iv-size-bits cm 64)
  (check-keystream-size-bytes cm "2^70")
  (check-test-vectors cm test-vectors)
  (check-test-suites cm test-suites))