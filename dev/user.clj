(ns user
  (:require [clojure.repl :refer :all]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer :all]
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            (net.ozias.crypt [libcrypt :refer :all]
                             [libbyte :refer :all])
            (net.ozias.crypt.cipher [cipher :as cipher]
                                    [blockcipher :as bc]
                                    [streamcipher :as sc])
            [net.ozias.crypt.cryptsuite :refer :all]))

(defn run-all-tests-azjure []
  (run-all-tests #"net.ozias.crypt\..*\..*test.*"))

(defn fmap [f map]
  (into {} (for [[key val] map] [key (f val)])))
