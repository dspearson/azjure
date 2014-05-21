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
  )
;(facts
;  "(v->str s)\n========================================"
;  (fact "non-vector" (v->str nil) => (throws AssertionError))
;  (fact "invalid byte (-1)" (v->str [-1]) => (throws AssertionError))
;  (fact "invalid byte (256)" (v->str [256]) => (throws AssertionError))
;  (fact "[74 97 115 111 110]" (v->str [74 97 115 111 110]) => "Jason"))
;(facts
;  "(str->v s)\n========================================"
;  (fact "non-string" (str->v nil) => (throws AssertionError))
;  (fact "Jason" (str->v "Jason") => [74 97 115 111 110]))
;
;(facts
;  "(v->base64 v)\n========================================"
;  (fact "non-vector" (v->base64 nil) => (throws AssertionError))
;  (fact "empty string" (v->base64 []) => "")
;  (fact "f" (v->base64 [102]) => "Zg==")
;  (fact "fo" (v->base64 [102 111]) => "Zm8=")
;  (fact "foo" (v->base64 [102 111 111]) => "Zm9v")
;  (fact "foob" (v->base64 [102 111 111 98]) => "Zm9vYg==")
;  (fact "fooba" (v->base64 [102 111 111 98 97]) => "Zm9vYmE=")
;  (fact "foobar" (v->base64 [102 111 111 98 97 114]) => "Zm9vYmFy")
;  (fact "Jason Grant Ozias"
;        (v->base64 (vec (.getBytes "Jason Grant Ozias"))) =>
;        "SmFzb24gR3JhbnQgT3ppYXM="))
;(facts
;  "(base64->v s)\n========================================"
;  (fact "non-string" (base64->v nil) => (throws AssertionError))
;  (fact "Zg==" (base64->v "Zg==") => [102])
;  (fact "Zm8=" (base64->v "Zm8=") => [102 111])
;  (fact "Zm9v" (base64->v "Zm9v") => [102 111 111])
;  (fact "Zm9vYg==" (base64->v "Zm9vYg==") => [102 111 111 98])
;  (fact "Zm9vYmE=" (base64->v "Zm9vYmE=") => [102 111 111 98 97])
;  (fact "Zm9vYmFy" (base64->v "Zm9vYmFy") => [102 111 111 98 97 114])
;  (fact "SmFzb24gR3JhbnQgT3ppYXM=" (base64->v "SmFzb24gR3JhbnQgT3ppYXM=") =>
;        [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]))
;
;(facts
;  "(v->base64url v)\n========================================"
;  (fact "non-vector" (v->base64url nil) => (throws AssertionError))
;  (fact "empty string" (v->base64url []) => "")
;  (fact "f" (v->base64url [102]) => "Zg==")
;  (fact "fo" (v->base64url [102 111]) => "Zm8=")
;  (fact "foo" (v->base64url [102 111 111]) => "Zm9v")
;  (fact "foob" (v->base64url [102 111 111 98]) => "Zm9vYg==")
;  (fact "fooba" (v->base64url [102 111 111 98 97]) => "Zm9vYmE=")
;  (fact "foobar" (v->base64url [102 111 111 98 97 114]) => "Zm9vYmFy")
;  (fact "[251 240]" (v->base64url [251 240 1]) => "-_AB")
;  (fact "Jason Grant Ozias"
;        (v->base64url (vec (.getBytes "Jason Grant Ozias"))) =>
;        "SmFzb24gR3JhbnQgT3ppYXM="))
;(facts
;  "(base64url->v s)\n========================================"
;  (fact "non-string" (base64url->v nil) => (throws AssertionError))
;  (fact "Zg==" (base64url->v "Zg==") => [102])
;  (fact "Zm8=" (base64url->v "Zm8=") => [102 111])
;  (fact "Zm9v" (base64url->v "Zm9v") => [102 111 111])
;  (fact "Zm9vYg==" (base64url->v "Zm9vYg==") => [102 111 111 98])
;  (fact "Zm9vYmE=" (base64url->v "Zm9vYmE=") => [102 111 111 98 97])
;  (fact "Zm9vYmFy" (base64url->v "Zm9vYmFy") => [102 111 111 98 97 114])
;  (fact "-_AB" (base64url->v "-_AB") => [251 240 1])
;  (fact "SmFzb24gR3JhbnQgT3ppYXM="
;        (base64url->v "SmFzb24gR3JhbnQgT3ppYXM=") =>
;        [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]))
;
;(facts
;  "(v->base32 v)\n========================================"
;  (fact "non-vector" (v->base32 nil) => (throws AssertionError))
;  (fact "empty string" (v->base32 []) => "")
;  (fact "f" (v->base32 [102]) => "MY======")
;  (fact "fo" (v->base32 [102 111]) => "MZXQ====")
;  (fact "foo" (v->base32 [102 111 111]) => "MZXW6===")
;  (fact "foob" (v->base32 [102 111 111 98]) => "MZXW6YQ=")
;  (fact "fooba" (v->base32 [102 111 111 98 97]) => "MZXW6YTB")
;  (fact "foobar" (v->base32 [102 111 111 98 97 114]) => "MZXW6YTBOI======")
;  (fact "Jason Grant Ozias"
;        (v->base32 (vec (.getBytes "Jason Grant Ozias"))) =>
;        "JJQXG33OEBDXEYLOOQQE66TJMFZQ===="))
;(facts
;  "(base32->v s)\n========================================"
;  (fact "non-string" (base32->v nil) => (throws AssertionError))
;  (fact "MY======" (base32->v "MY======") => [102])
;  (fact "MZXQ====" (base32->v "MZXQ====") => [102 111])
;  (fact "MZXW6===" (base32->v "MZXW6===") => [102 111 111])
;  (fact "MZXW6YQ=" (base32->v "MZXW6YQ=") => [102 111 111 98])
;  (fact "MZXW6YTB" (base32->v "MZXW6YTB") => [102 111 111 98 97])
;  (fact "MZXW6YTBOI======"
;        (base32->v "MZXW6YTBOI======") => [102 111 111 98 97 114])
;  (fact "JJQXG33OEBDXEYLOOQQE66TJMFZQ===="
;        (base32->v "JJQXG33OEBDXEYLOOQQE66TJMFZQ====") =>
;        [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]))
;
;(facts
;  "(v->base32hex v)\n========================================"
;  (fact "non-vector" (v->base32hex nil) => (throws AssertionError))
;  (fact "empty string" (v->base32hex []) => "")
;  (fact "f" (v->base32hex [102]) => "CO======")
;  (fact "fo" (v->base32hex [102 111]) => "CPNG====")
;  (fact "foo" (v->base32hex [102 111 111]) => "CPNMU===")
;  (fact "foob" (v->base32hex [102 111 111 98]) => "CPNMUOG=")
;  (fact "fooba" (v->base32hex [102 111 111 98 97]) => "CPNMUOJ1")
;  (fact "foobar" (v->base32hex [102 111 111 98 97 114]) => "CPNMUOJ1E8======")
;  (fact "Jason Grant Ozias"
;        (v->base32hex (vec (.getBytes "Jason Grant Ozias"))) =>
;        "99GN6RRE413N4OBEEGG4UUJ9C5PG===="))
;(facts
;  "(base32hex->v s)\n========================================"
;  (fact "non-string" (base32hex->v nil) => (throws AssertionError))
;  (fact "CO======" (base32hex->v "CO======") => [102])
;  (fact "CPNG====" (base32hex->v "CPNG====") => [102 111])
;  (fact "CPNMU===" (base32hex->v "CPNMU===") => [102 111 111])
;  (fact "CPNMUOG=" (base32hex->v "CPNMUOG=") => [102 111 111 98])
;  (fact "CPNMUOJ1" (base32hex->v "CPNMUOJ1") => [102 111 111 98 97])
;  (fact "CPNMUOJ1E8======"
;        (base32hex->v "CPNMUOJ1E8======") => [102 111 111 98 97 114])
;  (fact "99GN6RRE413N4OBEEGG4UUJ9C5PG===="
;        (base32hex->v "99GN6RRE413N4OBEEGG4UUJ9C5PG====") =>
;        [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]))
;
;(facts
;  "(v->base16 v)\n========================================"
;  (fact "non-vector" (v->base16 nil) => (throws AssertionError))
;  (fact "empty string" (v->base16 []) => "")
;  (fact "f" (v->base16 [102]) => "66")
;  (fact "fo" (v->base16 [102 111]) => "666F")
;  (fact "foo" (v->base16 [102 111 111]) => "666F6F")
;  (fact "foob" (v->base16 [102 111 111 98]) => "666F6F62")
;  (fact "fooba" (v->base16 [102 111 111 98 97]) => "666F6F6261")
;  (fact "foobar" (v->base16 [102 111 111 98 97 114]) => "666F6F626172")
;  (fact "Jason Grant Ozias"
;        (v->base16 (vec (.getBytes "Jason Grant Ozias"))) =>
;        "4A61736F6E204772616E74204F7A696173"))
;(facts
;  "(base16->v s)\n========================================"
;  (fact "non-string" (base16->v nil) => (throws AssertionError))
;  (fact "66" (base16->v "66") => [102])
;  (fact "666F" (base16->v "666F") => [102 111])
;  (fact "666F6F" (base16->v "666F6F") => [102 111 111])
;  (fact "666F6F62" (base16->v "666F6F62") => [102 111 111 98])
;  (fact "666F6F6261" (base16->v "666F6F6261") => [102 111 111 98 97])
;  (fact "666F6F626172"
;        (base16->v "666F6F626172") => [102 111 111 98 97 114])
;  (fact "4A61736F6E204772616E74204F7A696173"
;        (base16->v "4A61736F6E204772616E74204F7A696173") =>
;        [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]))
;
;(facts
;  "(output-encoder m bv & keys)\n========================================"
;  (fact "v->str encryption"
;        (output-encoder {:eoe :str} [102 111 111 98 97 114])
;        => "foobar")
;  (fact "v->str decryption"
;        (output-encoder {:doe :str} [102 111 111 98 97 114] :encryption false)
;        => "foobar")
;  (fact "v->hex encryption"
;        (output-encoder {:eoe :hex} [102 111 111 98 97 114])
;        => "666f6f626172")
;  (fact "v->hex decryption"
;        (output-encoder {:doe :hex} [102 111 111 98 97 114] :encryption false)
;        => "666f6f626172")
;  (fact "v->base64 encryption"
;        (output-encoder {:eoe :base64} [102 111 111 98 97 114])
;        => "Zm9vYmFy")
;  (fact "v->base64 decryption"
;        (output-encoder {:doe :base64}
;                        [102 111 111 98 97 114]
;                        :encryption false)
;        => "Zm9vYmFy")
;  (fact "v->base64url encryption"
;        (output-encoder {:eoe :base64url} [102 111 111 98 97 114])
;        => "Zm9vYmFy")
;  (fact "v->base64url decryption"
;        (output-encoder {:doe :base64url}
;                        [102 111 111 98 97 114]
;                        :encryption false)
;        => "Zm9vYmFy")
;  (fact "v->base32 encryption"
;        (output-encoder {:eoe :base32} [102 111 111 98 97 114])
;        => "MZXW6YTBOI======")
;  (fact "v->base32 decryption"
;        (output-encoder {:doe :base32}
;                        [102 111 111 98 97 114]
;                        :encryption false)
;        => "MZXW6YTBOI======")
;  (fact "v->base32hex encryption"
;        (output-encoder {:eoe :base32hex} [102 111 111 98 97 114])
;        => "CPNMUOJ1E8======")
;  (fact "v->base32hex decryption"
;        (output-encoder {:doe :base32hex}
;                        [102 111 111 98 97 114]
;                        :encryption false)
;        => "CPNMUOJ1E8======")
;  (fact "v->base16 encryption"
;        (output-encoder {:eoe :base16} [102 111 111 98 97 114])
;        => "666F6F626172")
;  (fact "v->base16 decryption"
;        (output-encoder {:doe :base16}
;                        [102 111 111 98 97 114]
;                        :encryption false)
;        => "666F6F626172"))
;
;(facts
;  "(input-decoder m bv & keys)\n========================================"
;  (fact "str->v encryption"
;        (input-decoder {:eid :str} "foobar")
;        => [102 111 111 98 97 114])
;  (fact "str->v decryption"
;        (input-decoder {:did :str} "foobar" :encryption false)
;        => [102 111 111 98 97 114])
;  (fact "hex->v encryption"
;        (input-decoder {:eid :hex} "666f6f626172")
;        => [102 111 111 98 97 114])
;  (fact "hex->v decryption"
;        (input-decoder {:did :hex} "666f6f626172" :encryption false)
;        => [102 111 111 98 97 114])
;  (fact "base64->v encryption"
;        (input-decoder {:eid :base64} "Zm9vYmFy")
;        => [102 111 111 98 97 114])
;  (fact "base64->v decryption"
;        (input-decoder {:did :base64}
;                       "Zm9vYmFy"
;                       :encryption false)
;        => [102 111 111 98 97 114])
;  (fact "base64url->v encryption"
;        (input-decoder {:eid :base64url} "Zm9vYmFy")
;        => [102 111 111 98 97 114])
;  (fact "base64url->v decryption"
;        (input-decoder {:did :base64url}
;                       "Zm9vYmFy"
;                       :encryption false)
;        => [102 111 111 98 97 114])
;  (fact "base32->v encryption"
;        (input-decoder {:eid :base32} "MZXW6YTBOI======")
;        => [102 111 111 98 97 114])
;  (fact "base32->v decryption"
;        (input-decoder {:did :base32}
;                       "MZXW6YTBOI======"
;                       :encryption false)
;        => [102 111 111 98 97 114])
;  (fact "base32hex->v encryption"
;        (input-decoder {:eid :base32hex} "CPNMUOJ1E8======")
;        => [102 111 111 98 97 114])
;  (fact "base32hex->v decryption"
;        (input-decoder {:did :base32hex}
;                       "CPNMUOJ1E8======"
;                       :encryption false)
;        => [102 111 111 98 97 114])
;  (fact "base16->v encryption"
;        (input-decoder {:eid :base16} "666F6F626172")
;        => [102 111 111 98 97 114])
;  (fact "base16->v decryption"
;        (input-decoder {:did :base16}
;                       "666F6F626172"
;                       :encryption false)
;        => [102 111 111 98 97 114]))