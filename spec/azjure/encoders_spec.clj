(ns azjure.encoders-spec
  (:require [azjure.encoders :refer :all]
            [speclj.core :refer :all]))

(describe
  "encoders"
  (context
    "x->hex"
    (with two-digit-hex
          '("00" "01" "02" "03" "04" "05" "06" "07" "08" "09" "0a" "0b" "0c"
            "0d" "0e" "0f" "10" "11" "12" "13" "14" "15" "16" "17" "18" "19"
            "1a" "1b" "1c" "1d" "1e" "1f" "20" "21" "22" "23" "24" "25" "26"
            "27" "28" "29" "2a" "2b" "2c" "2d" "2e" "2f" "30" "31" "32" "33"
            "34" "35" "36" "37" "38" "39" "3a" "3b" "3c" "3d" "3e" "3f" "40"
            "41" "42" "43" "44" "45" "46" "47" "48" "49" "4a" "4b" "4c" "4d"
            "4e" "4f" "50" "51" "52" "53" "54" "55" "56" "57" "58" "59" "5a"
            "5b" "5c" "5d" "5e" "5f" "60" "61" "62" "63" "64" "65" "66" "67"
            "68" "69" "6a" "6b" "6c" "6d" "6e" "6f" "70" "71" "72" "73" "74"
            "75" "76" "77" "78" "79" "7a" "7b" "7c" "7d" "7e" "7f" "80" "81"
            "82" "83" "84" "85" "86" "87" "88" "89" "8a" "8b" "8c" "8d" "8e"
            "8f" "90" "91" "92" "93" "94" "95" "96" "97" "98" "99" "9a" "9b"
            "9c" "9d" "9e" "9f" "a0" "a1" "a2" "a3" "a4" "a5" "a6" "a7" "a8"
            "a9" "aa" "ab" "ac" "ad" "ae" "af" "b0" "b1" "b2" "b3" "b4" "b5"
            "b6" "b7" "b8" "b9" "ba" "bb" "bc" "bd" "be" "bf" "c0" "c1" "c2"
            "c3" "c4" "c5" "c6" "c7" "c8" "c9" "ca" "cb" "cc" "cd" "ce" "cf"
            "d0" "d1" "d2" "d3" "d4" "d5" "d6" "d7" "d8" "d9" "da" "db" "dc"
            "dd" "de" "df" "e0" "e1" "e2" "e3" "e4" "e5" "e6" "e7" "e8" "e9"
            "ea" "eb" "ec" "ed" "ee" "ef" "f0" "f1" "f2" "f3" "f4" "f5" "f6"
            "f7" "f8" "f9" "fa" "fb" "fc" "fd" "fe" "ff"))
    (it "should throw an AssertionError on x < 0"
        (should-throw AssertionError (x->hex -1)))
    (it "should throw an AssertionError on x >255"
        (should-throw AssertionError (x->hex 256)))
    (it "should generate two digit hex strings"
        (should= @two-digit-hex (map x->hex (range 256)))))
  (context
    "hex->x"
    (it "should throw an AssertionError on non-string input"
        (should-throw AssertionError (hex->x nil)))
    (it "should throw an AssertionError on short input"
        (should-throw AssertionError (hex->x "")))
    (it "should throw an AssertionError on long input"
        (should-throw AssertionError (hex->x "000")))
    (it "should equal 0" (should= 0 (hex->x "0")))
    (it "should equal 0" (should= 0 (hex->x "00")))
    (it "should equal 15" (should= 15 (hex->x "0f")))
    (it "should equal 170" (should= 170 (hex->x "aa")))
    (it "should equal 255" (should= 255 (hex->x "FF"))))
  (context
    "v->hex"
    (it "should throw an AssertionError on a non-vector"
        (should-throw AssertionError (v->hex nil)))
    (it "should throw an AssertionError on an invalid byte value (-1)"
        (should-throw AssertionError (v->hex [-1 0 1])))
    (it "should throw an AssertionError on an invalid byte value (256)"
        (should-throw AssertionError (v->hex [0 256 1])))
    (it "should generate '01'"
        (should= "01" (v->hex [1])))
    (it "should generate 'ff'"
        (should= "ff" (v->hex [255])))
    (it "should generate '01000000"
        (should= "01000000" (v->hex [1 0 0 0])))
    (it "should generate '10162d08'"
        (should= "10162d08" (v->hex [16 22 45 8]))))
  (context
    "hex->v"
    (it "should throw an AssertionError on a non-string"
        (should-throw AssertionError (hex->v nil)))
    (it "should be '[0]'"
        (should= [0] (hex->v "0")))
    (it "should be '[1 0]'"
        (should= [1 0] (hex->v "100")))
    (it "should be '[1 255]'"
        (should= [1 255] (hex->v "1ff")))
    (it "should be '[0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]'"
        (should= [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 (hex->v "123456789abcdef")))
    (it "should be '[0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]'"
        (should= [0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF]
                 (hex->v "0123456789abcdef"))))
  (context
    "v->str"
    (it "should throw an AssertionError on a non-vector"
        (should-throw AssertionError (v->str nil)))
    (it "should throw an AssertionError on an invalid byte (-1)"
        (should-throw AssertionError (v->str [-1])))
    (it "should throw an AssertionError on an invalid byte (256)"
        (should-throw AssertionError (v->str [256])))
    (it "should generate the string 'Jason'"
        (should= "Jason" (v->str [74 97 115 111 110]))))
  (context
    "str->v"
    (it "should throw an AssertionError on a non-string"
        (should-throw AssertionError (str->v nil)))
    (it "should generate [74 97 115 111 110]"
        (should= [74 97 115 111 110] (str->v "Jason"))))
  (context
    "v->base64"
    (it "should throw an AssertionError on a non-vector"
        (should-throw AssertionError (v->base64 nil)))
    (it "should generate an empty string"
        (should= "" (v->base64 [])))
    (it "should generate 'Zg=='"
        (should= "Zg==" (v->base64 [102])))
    (it "should generate 'Zm8='"
        (should= "Zm8=" (v->base64 [102 111])))
    (it "should generate 'Zm9v'"
        (should= "Zm9v" (v->base64 [102 111 111])))
    (it "should generate 'Zm9vYg=='"
        (should= "Zm9vYg==" (v->base64 [102 111 111 98])))
    (it "should generate 'Zm9vYmE='"
        (should= "Zm9vYmE=" (v->base64 [102 111 111 98 97])))
    (it "should generate 'Zm9vYmFy'"
        (should= "Zm9vYmFy" (v->base64 [102 111 111 98 97 114])))
    (it "should generate 'SmFzb24gR3JhbnQgT3ppYXM='"
        (should= "SmFzb24gR3JhbnQgT3ppYXM="
                 (v->base64 (vec (.getBytes "Jason Grant Ozias"))))))
  (context
    "base64->v"
    (it "should throw an AssertionError on a non-string"
        (should-throw AssertionError (base64->v nil)))
    (it "should generate [102]"
        (should= [102] (base64->v "Zg==")))
    (it "should generate [102 111]"
        (should= [102 111] (base64->v "Zm8=")))
    (it "should generate [102 111 111]"
        (should= [102 111 111] (base64->v "Zm9v")))
    (it "should generate [102 111 111 98]"
        (should= [102 111 111 98] (base64->v "Zm9vYg==")))
    (it "should generate [102 111 111 98 97]"
        (should= [102 111 111 98 97] (base64->v "Zm9vYmE=")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (base64->v "Zm9vYmFy")))
    (it "should generate [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105
    97 115]"
        (should= [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]
                 (base64->v "SmFzb24gR3JhbnQgT3ppYXM="))))
  (context
    "v->base64url"
    (it "should throw an AssertionError on a non-vector"
        (should-throw AssertionError (v->base64url nil)))
    (it "should generate an empty string"
        (should= "" (v->base64url [])))
    (it "should generate 'Zg=='"
        (should= "Zg==" (v->base64url [102])))
    (it "should generate 'Zm8='"
        (should= "Zm8=" (v->base64url [102 111])))
    (it "should generate 'Zm9v'"
        (should= "Zm9v" (v->base64url [102 111 111])))
    (it "should generate 'Zm9vYg=='"
        (should= "Zm9vYg==" (v->base64url [102 111 111 98])))
    (it "should generate 'Zm9vYmE='"
        (should= "Zm9vYmE=" (v->base64url [102 111 111 98 97])))
    (it "should generate 'Zm9vYmFy'"
        (should= "Zm9vYmFy" (v->base64url [102 111 111 98 97 114])))
    (it "should generate 'SmFzb24gR3JhbnQgT3ppYXM='"
        (should= "SmFzb24gR3JhbnQgT3ppYXM="
                 (v->base64url (vec (.getBytes "Jason Grant Ozias"))))))
  (context
    "base64url->v"
    (it "should throw an AssertionError on a non-string"
        (should-throw AssertionError (base64url->v nil)))
    (it "should generate [102]"
        (should= [102] (base64url->v "Zg==")))
    (it "should generate [102 111]"
        (should= [102 111] (base64url->v "Zm8=")))
    (it "should generate [102 111 111]"
        (should= [102 111 111] (base64url->v "Zm9v")))
    (it "should generate [102 111 111 98]"
        (should= [102 111 111 98] (base64url->v "Zm9vYg==")))
    (it "should generate [102 111 111 98 97]"
        (should= [102 111 111 98 97] (base64url->v "Zm9vYmE=")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (base64url->v "Zm9vYmFy")))
    (it "should generate [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105
    97 115]"
        (should= [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]
                 (base64url->v "SmFzb24gR3JhbnQgT3ppYXM="))))
  (context
    "v->base32"
    (it "should throw an AssertionError on a non-vector"
        (should-throw AssertionError (v->base32 nil)))
    (it "should generate an empty string"
        (should= "" (v->base32 [])))
    (it "should generate 'MY======'"
        (should= "MY======" (v->base32 [102])))
    (it "should generate 'MZXQ===='"
        (should= "MZXQ====" (v->base32 [102 111])))
    (it "should generate 'MZXW6==='"
        (should= "MZXW6===" (v->base32 [102 111 111])))
    (it "should generate 'MZXW6YQ='"
        (should= "MZXW6YQ=" (v->base32 [102 111 111 98])))
    (it "should generate 'MZXW6YTB'"
        (should= "MZXW6YTB" (v->base32 [102 111 111 98 97])))
    (it "should generate 'MZXW6YTBOI======'"
        (should= "MZXW6YTBOI======" (v->base32 [102 111 111 98 97 114])))
    (it "should generate 'JJQXG33OEBDXEYLOOQQE66TJMFZQ===='"
        (should= "JJQXG33OEBDXEYLOOQQE66TJMFZQ===="
                 (v->base32 (vec (.getBytes "Jason Grant Ozias"))))))
  (context
    "base32->v"
    (it "should throw an AssertionError on a non-string"
        (should-throw AssertionError (base32->v nil)))
    (it "should generate [102]"
        (should= [102] (base32->v "MY======")))
    (it "should generate [102 111]"
        (should= [102 111] (base32->v "MZXQ====")))
    (it "should generate [102 111 111]"
        (should= [102 111 111] (base32->v "MZXW6===")))
    (it "should generate [102 111 111 98]"
        (should= [102 111 111 98] (base32->v "MZXW6YQ=")))
    (it "should generate [102 111 111 98 97]"
        (should= [102 111 111 98 97] (base32->v "MZXW6YTB")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (base32->v "MZXW6YTBOI======")))
    (it "should generate [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105
    97 115]"
        (should= [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]
                 (base32->v "JJQXG33OEBDXEYLOOQQE66TJMFZQ===="))))
  (context
    "v->base32hex"
    (it "should throw an AssertionError on a non-vector"
        (should-throw AssertionError (v->base32hex nil)))
    (it "should generate an empty string"
        (should= "" (v->base32hex [])))
    (it "should generate 'CO======'"
        (should= "CO======" (v->base32hex [102])))
    (it "should generate 'CPNG===='"
        (should= "CPNG====" (v->base32hex [102 111])))
    (it "should generate 'CPNMU==='"
        (should= "CPNMU===" (v->base32hex [102 111 111])))
    (it "should generate 'CPNMUOG='"
        (should= "CPNMUOG=" (v->base32hex [102 111 111 98])))
    (it "should generate 'CPNMUOJ1'"
        (should= "CPNMUOJ1" (v->base32hex [102 111 111 98 97])))
    (it "should generate 'CPNMUOJ1E8======'"
        (should= "CPNMUOJ1E8======" (v->base32hex [102 111 111 98 97 114])))
    (it "should generate '99GN6RRE413N4OBEEGG4UUJ9C5PG===='"
        (should= "99GN6RRE413N4OBEEGG4UUJ9C5PG===="
                 (v->base32hex (vec (.getBytes "Jason Grant Ozias"))))))
  (context
    "base32hex->v"
    (it "should throw an AssertionError on a non-string"
        (should-throw AssertionError (base32hex->v nil)))
    (it "should generate [102]"
        (should= [102] (base32hex->v "CO======")))
    (it "should generate [102 111]"
        (should= [102 111] (base32hex->v "CPNG====")))
    (it "should generate [102 111 111]"
        (should= [102 111 111] (base32hex->v "CPNMU===")))
    (it "should generate [102 111 111 98]"
        (should= [102 111 111 98] (base32hex->v "CPNMUOG=")))
    (it "should generate [102 111 111 98 97]"
        (should= [102 111 111 98 97] (base32hex->v "CPNMUOJ1")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (base32hex->v "CPNMUOJ1E8======")))
    (it "should generate [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105
    97 115]"
        (should= [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]
                 (base32hex->v "99GN6RRE413N4OBEEGG4UUJ9C5PG===="))))
  (context
    "v->base16"
    (it "should throw an AssertionError on a non-vector"
        (should-throw AssertionError (v->base16 nil)))
    (it "should generate an empty string"
        (should= "" (v->base16 [])))
    (it "should generate '66'"
        (should= "66" (v->base16 [102])))
    (it "should generate '666F'"
        (should= "666F" (v->base16 [102 111])))
    (it "should generate '666F6F'"
        (should= "666F6F" (v->base16 [102 111 111])))
    (it "should generate '666F6F62'"
        (should= "666F6F62" (v->base16 [102 111 111 98])))
    (it "should generate '666F6F6261'"
        (should= "666F6F6261" (v->base16 [102 111 111 98 97])))
    (it "should generate '666F6F626172'"
        (should= "666F6F626172" (v->base16 [102 111 111 98 97 114])))
    (it "should generate '4A61736F6E204772616E74204F7A696173'"
        (should= "4A61736F6E204772616E74204F7A696173"
                 (v->base16 (vec (.getBytes "Jason Grant Ozias"))))))
  (context
    "base16->v"
    (it "should throw an AssertionError on a non-string"
        (should-throw AssertionError (base16->v nil)))
    (it "should generate [102]"
        (should= [102] (base16->v "66")))
    (it "should generate [102 111]"
        (should= [102 111] (base16->v "666F")))
    (it "should generate [102 111 111]"
        (should= [102 111 111] (base16->v "666F6F")))
    (it "should generate [102 111 111 98]"
        (should= [102 111 111 98] (base16->v "666F6F62")))
    (it "should generate [102 111 111 98 97]"
        (should= [102 111 111 98 97] (base16->v "666F6F6261")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (base16->v "666F6F626172")))
    (it "should generate [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105
    97 115]"
        (should= [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]
                 (base16->v "4A61736F6E204772616E74204F7A696173"))))
  (context
    "output-encoder"
    (it "should generate 'foobar'"
        (should= "foobar" (output-encoder {:eoe :str}
                                          [102 111 111 98 97 114])))
    (it "should generate 'foobar'"
        (should= "foobar" (output-encoder {:doe :str}
                                          [102 111 111 98 97 114]
                                          :encryption false)))
    (it "should generate '666f6f626172'"
        (should= "666f6f626172" (output-encoder {:eoe :hex}
                                                [102 111 111 98 97 114])))
    (it "should generate '666f6f626172'"
        (should= "666f6f626172" (output-encoder {:doe :hex}
                                                [102 111 111 98 97 114]
                                                :encryption false)))
    (it "should generate 'Zm9vYmFy'"
        (should= "Zm9vYmFy" (output-encoder {:eoe :base64}
                                            [102 111 111 98 97 114])))
    (it "should generate 'Zm9vYmFy'"
        (should= "Zm9vYmFy" (output-encoder {:doe :base64}
                                            [102 111 111 98 97 114]
                                            :encryption false)))
    (it "should generate 'Zm9vYmFy'"
        (should= "Zm9vYmFy" (output-encoder {:eoe :base64url}
                                            [102 111 111 98 97 114])))
    (it "should generate 'Zm9vYmFy'"
        (should= "Zm9vYmFy" (output-encoder {:doe :base64url}
                                            [102 111 111 98 97 114]
                                            :encryption false)))
    (it "should generate 'MZXW6YTBOI======'"
        (should= "MZXW6YTBOI======" (output-encoder {:eoe :base32}
                                                    [102 111 111 98 97 114])))
    (it "should generate 'MZXW6YTBOI======'"
        (should= "MZXW6YTBOI======" (output-encoder {:doe :base32}
                                                    [102 111 111 98 97 114]
                                                    :encryption false)))
    (it "should generate 'CPNMUOJ1E8======'"
        (should= "CPNMUOJ1E8======" (output-encoder {:eoe :base32hex}
                                                    [102 111 111 98 97 114])))
    (it "should generate 'CPNMUOJ1E8======'"
        (should= "CPNMUOJ1E8======" (output-encoder {:doe :base32hex}
                                                    [102 111 111 98 97 114]
                                                    :encryption false)))
    (it "should generate '666F6F626172'"
        (should= "666F6F626172" (output-encoder {:eoe :base16}
                                                [102 111 111 98 97 114])))
    (it "should generate '666F6F626172'"
        (should= "666F6F626172" (output-encoder {:doe :base16}
                                                [102 111 111 98 97 114]
                                                :encryption false))))
  (context
    "input-decoder"
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:eid :str}
                                                        "foobar")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:did :str}
                                                        "foobar"
                                                        :encryption false)))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:eid :hex}
                                                        "666f6f626172")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:did :hex}
                                                        "666f6f626172"
                                                        :encryption false)))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:eid :base64}
                                                        "Zm9vYmFy")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:did :base64}
                                                        "Zm9vYmFy"
                                                        :encryption false)))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:eid :base64url}
                                                        "Zm9vYmFy")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:did :base64url}
                                                        "Zm9vYmFy"
                                                        :encryption false)))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:eid :base32}
                                                        "MZXW6YTBOI======")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:did :base32}
                                                        "MZXW6YTBOI======"
                                                        :encryption false)))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:eid :base32hex}
                                                        "CPNMUOJ1E8======")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:did :base32hex}
                                                        "CPNMUOJ1E8======"
                                                        :encryption false)))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:eid :base16}
                                                        "666F6F626172")))
    (it "should generate [102 111 111 98 97 114]"
        (should= [102 111 111 98 97 114] (input-decoder {:did :base16}
                                                        "666F6F626172"
                                                        :encryption false)))))