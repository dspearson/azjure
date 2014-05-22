(ns azjure.cipher.cast5-spec
  (:require [azjure.libtest :refer :all]
            [speclj.core :refer :all]))

(def ^{:private true
       :doc     "Test vectors as defined in the spec."}
  test-vectors [
                 ;[[0x01 0x23 0x45 0x67 0x12 0x34 0x56 0x78
                 ; 0x23 0x45 0x67 0x89 0x34 0x56 0x78 0x9A]
                 ;[0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 ;[0x23 0x8B 0x4F 0xE5 0x84 0x7E 0x44 0xB2]]
                 ])

(def ^{:private true
       :doc     "Suite tests"}
  test-suites [
                ;[:ecb :iso7816 ct-64-bf-ecb-iso7186]
                ;[:ecb :iso10126 ct-64-bf-ecb-base]
                ;[:ecb :pkcs7 ct-64-bf-ecb-pkcs7]
                ;[:ecb :x923 ct-64-bf-ecb-x923]
                ;[:ecb :zero ct-64-bf-ecb-zero]
                ;[:cbc :iso7816 ct-64-bf-cbc-iso7186]
                ;[:cbc :iso10126 ct-64-bf-cbc-base]
                ;[:cbc :pkcs7 ct-64-bf-cbc-pkcs7]
                ;[:cbc :x923 ct-64-bf-cbc-x923]
                ;[:cbc :zero ct-64-bf-cbc-zero]
                ;[:pcbc :iso7816 ct-64-bf-pcbc-iso7186]
                ;[:pcbc :iso10126 ct-64-bf-pcbc-base]
                ;[:pcbc :pkcs7 ct-64-bf-pcbc-pkcs7]
                ;[:pcbc :x923 ct-64-bf-pcbc-x923]
                ;[:pcbc :zero ct-64-bf-pcbc-zero]
                ;[:cfb :iso7816 ct-64-bf-cfb-iso7186]
                ;[:cfb :iso10126 ct-64-bf-cfb-base]
                ;[:cfb :pkcs7 ct-64-bf-cfb-pkcs7]
                ;[:cfb :x923 ct-64-bf-cfb-x923]
                ;[:cfb :zero ct-64-bf-cfb-zero]
                ;[:ofb :iso7816 ct-64-bf-ofb-iso7186]
                ;[:ofb :iso10126 ct-64-bf-ofb-base]
                ;[:ofb :pkcs7 ct-64-bf-ofb-pkcs7]
                ;[:ofb :x923 ct-64-bf-ofb-x923]
                ;[:ofb :zero ct-64-bf-ofb-zero]
                ;[:ctr :iso7816 ct-64-bf-ctr-iso7186]
                ;[:ctr :iso10126 ct-64-bf-ctr-base]
                ;[:ctr :pkcs7 ct-64-bf-ctr-pkcs7]
                ;[:ctr :x923 ct-64-bf-ctr-x923]
                ;[:ctr :zero ct-64-bf-ctr-zero]
                ])

(def ^{:private true
       :doc     "Configuration Map"}
  cm {:type :cast5 :eid :str :doe :str})

(describe
  "CAST5"
  (check-blocksize cm 64)
  (check-keysizes cm (range 40 129 8))
  (check-test-vectors cm test-vectors)
  (check-test-suites cm test-suites))