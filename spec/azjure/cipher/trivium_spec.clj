(ns azjure.cipher.trivium-spec
  (:require [azjure.libtest :refer :all]
            [speclj.core :refer :all]))

(def ^{:private true
       :doc "Configuration Map"}
  cm {:type :trivium})

(describe
  "Trivium"
  (check-keysizes cm [80])
  (check-iv-size-bits cm 80)
  (check-keystream-size-bytes cm "2^64"))
