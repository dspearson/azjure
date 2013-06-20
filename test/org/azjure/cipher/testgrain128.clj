;; # Grain128 Stream Cipher Tests

(ns ^{:author "Jason Ozias"
      :doc "Test suite for the Grain128 stream cipher"}
  org.azjure.cipher.testgrain128
  (:require [clojure.test :refer :all]
            (org.azjure [libtest :refer :all]
                        [testivs :refer :all]
                        [testkeys :refer :all]
                        [testplaintext :refer :all]
                        [testciphertext :refer :all])
            (org.azjure.cipher [cipher :as cipher]
                               [streamcipher :as sc]
                               [grain128 :refer (->Grain128)])))
;; ### Record Definitions

(def ^{:doc "Grain128 record to be used in the tests"} grain128 (->Grain128))
