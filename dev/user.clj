(ns user
  (:require [clojure.repl :refer :all]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer :all]
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            [taoensso.timbre.profiling :as profiling :refer (p profile)]
            (org.azjure [cryptsuite :as cs :refer :all]
                        [libcrypt :refer :all]
                        [libbyte :refer :all]
                        [testkeys :refer :all]
                        [testivs :refer :all]
                        [testplaintext :refer :all]
                        [testciphertext :refer :all])
            (org.azjure.cipher [cipher :as cipher]
                               [blockcipher :as bc]
                               [streamcipher :as sc]
                               [aes :refer (->Aes)]
                               [blowfish :refer (->Blowfish)]
                               [cast5 :refer (->CAST5)]
                               [cast6 :refer (->CAST6)]
                               [tea :refer (->TEA)]
                               [twofish :refer (->Twofish)]
                               [xtea :refer (->XTEA)]
                               [chacha :refer (->Chacha)]
                               [grain128 :refer (->Grain128)]
                               [hc128 :refer (->HC128)]
                               [hc256 :refer (->HC256)]
                               [mickey2 :refer (->Mickey2)]
                               [rabbit :refer (->Rabbit)]
                               [salsa20 :refer (->Salsa20)]
                               [trivium :refer (->Trivium)])
            [org.azjure.cryptsuite :refer :all]))

(defn run-all-tests-azjure []
  (run-all-tests #"org.azjure\..*\..*test.*"))

(defn fmap [f map]
  (into {} (for [[key val] map] [key (f val)])))
