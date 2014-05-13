(ns azjure.testencoders
  (:require [azjure.encoders :refer :all]
            [midje.config :as config]
            [midje.sweet :refer :all]
            [midje.util :refer [expose-testables]]))

(def ^{:private true :doc "The base64 alphabet string"} b64-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(def ^{:private true :doc "The base64url alphabet string"} b64url-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(expose-testables azjure.encoders)

(config/at-print-level
  :print-facts
  (facts
    "about x->hex"
    (fact "x < 0" (x->hex -1) => (throws AssertionError))
    (fact "0 >= x >= 255"
          (map x->hex (range 256)) =>
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
    (fact "x > 255" (x->hex 256) => (throws AssertionError)))
  (facts
    "about hex->x"
    (fact "non-string" (hex->x nil) => (throws AssertionError))
    (fact "string too short" (hex->x "") => (throws AssertionError))
    (fact "0" (hex->x "0") => 0)
    (fact "00" (hex->x "00") => 0)
    (fact "0f" (hex->x "0f") => 15)
    (fact "aa" (hex->x "aa") => 170)
    (fact "FF" (hex->x "FF") => 255)
    (fact "string too long" (hex->x "000") => (throws AssertionError)))
  (facts
    "about v->hex"
    (fact "non-vector" (v->hex nil) => (throws AssertionError))
    (fact "invalid byte value (-1)"
          (v->hex [-1 0 1]) => (throws AssertionError))
    (fact "invalid byte value (256)"
          (v->hex [0 256 1]) => (throws AssertionError))
    (fact "[1]" (v->hex [1]) => "01")
    (fact "[255]" (v->hex [255]) => "ff")
    (fact "[1 0 0 0]" (v->hex [1 0 0 0]) => "01000000")
    (fact "[16 22 45 8]" (v->hex [16 22 45 8]) => "10162d08"))
  (facts
    "about hex->v"
    (fact "non-string" (hex->v nil) => (throws AssertionError))
    (fact "0" (hex->v "0") => [0])
    (fact "100" (hex->v "100") => [1 0])
    (fact "1ff" (hex->v "1ff") => [1 255])
    (fact "01ff" (hex->v "01ff") => [1 255])
    (fact "123456789abcdef"
          (hex->v "123456789abcdef") => [1 35 69 103 137 171 205 239])
    (fact "0123456789abcdef"
          (hex->v "0123456789abcdef") => [1 35 69 103 137 171 205 239]))
  (facts
    "about v->str"
    (fact "non-vector" (v->str nil) => (throws AssertionError))
    (fact "invalid byte (-1)" (v->str [-1]) => (throws AssertionError))
    (fact "invalid byte (256)" (v->str [256]) => (throws AssertionError))
    (fact "[74 97 115 111 110]" (v->str [74 97 115 111 110]) => "Jason"))
  (facts
    "about str->v"
    (fact "non-string" (str->v nil) => (throws AssertionError))
    (fact "Jason" (str->v "Jason") => [74 97 115 111 110]))
  (facts
    "about nth6bits"
    (fact "invalid x value (-1)" (nth6bits -1 0) => (throws AssertionError))
    (fact "invalid x value (2^24)"
          (nth6bits 16777216 0) => (throws AssertionError))
    (fact "invalid n value (-1)" (nth6bits 0 -1) => (throws AssertionError))
    (fact "invalid n value (4)" (nth6bits 0 4) => (throws AssertionError))
    (fact "2^24 - 1 0th" (nth6bits 16777215 0) => 63)
    (fact "2^24 - 1 1st" (nth6bits 16777215 1) => 63)
    (fact "2^24 - 1 2nd" (nth6bits 16777215 2) => 63)
    (fact "2^24 - 1 3rd" (nth6bits 16777215 3) => 63)
    (fact "14712327 0th" (nth6bits 14712327 0) => 7)
    (fact "14712327 1st" (nth6bits 14712327 1) => 56)
    (fact "14712327 2nd" (nth6bits 14712327 2) => 7)
    (fact "14712327 3rd" (nth6bits 14712327 3) => 56))
  (facts
    "about v->base64x"
    (fact "alphabet not string"
          (v->base64x [] nil) => (throws AssertionError))
    (fact "alphabet too short"
          (v->base64x [] "abc123") => (throws AssertionError))
    (fact "v not vector"
          (v->base64x nil b64-alphabet) => (throws AssertionError))
    (fact "invalid byte in v (-1)"
          (v->base64x [-1] b64-alphabet) => (throws AssertionError))
    (fact "invalid byte in v (256)"
          (v->base64x [256] b64-alphabet) => (throws AssertionError))
    (fact "[74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]"
          (v->base64x
            [74 97 115 111 110 32 71 114 97 110 116 32 79 122 105 97 115]
            b64-alphabet) => "SmFzb24gR3JhbnQgT3ppYXM=")
    (fact "empty vector" (v->base64x [] b64-alphabet) => "")
    (fact "f" (v->base64x [102] b64-alphabet) => "Zg==")
    (fact "fo" (v->base64x [102 111] b64-alphabet) => "Zm8=")
    (fact "foo" (v->base64x [102 111 111] b64-alphabet) => "Zm9v")
    (fact "foob" (v->base64x [102 111 111 98] b64-alphabet) => "Zm9vYg==")
    (fact "fooba" (v->base64x [102 111 111 98 97] b64-alphabet) => "Zm9vYmE=")
    (fact "foobar"
          (v->base64x [102 111 111 98 97 114] b64-alphabet) => "Zm9vYmFy"))
  (facts
    "about nth5bits"
    (fact "invalid x value (-1)" (nth6bits -1 0) => (throws AssertionError))
    (fact "invalid x value (2^40)"
          (nth6bits 1099511627776 0) => (throws AssertionError))
    (fact "invalid n value (-1)" (nth6bits 0 -1) => (throws AssertionError))
    (fact "invalid n value (8)" (nth6bits 0 8) => (throws AssertionError))
    (fact "567489872400 0th" (nth5bits 567489872400 0) => 16)
    (fact "567489872400 1st" (nth5bits 567489872400 1) => 16)
    (fact "567489872400 2nd" (nth5bits 567489872400 2) => 16)
    (fact "567489872400 3rd" (nth5bits 567489872400 3) => 16)
    (fact "567489872400 4th" (nth5bits 567489872400 4) => 16)
    (fact "567489872400 5th" (nth5bits 567489872400 5) => 16)
    (fact "567489872400 6th" (nth5bits 567489872400 6) => 16)
    (fact "567489872400 7th" (nth5bits 567489872400 7) => 16))
  )