(ns azjure.cipher.chacha-spec
  (:require [azjure.libtest :refer :all]
            [speclj.core :refer :all]))

(def ^{:private true
       :doc     "Configuration Map"}
  cm {:type :chacha})

(describe
  "ChaCha"
  (check-keysizes cm [128 256])
  (check-iv-size-bits cm 64)
  (check-keystream-size-bytes cm "2^70"))