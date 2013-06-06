(ns user
  (:require [clojure.repl :refer :all]
            [clojure.pprint :refer (pprint)]
            [clojure.test :refer :all]
            [clojure.tools.namespace.repl :refer (refresh refresh-all)]
            (net.ozias.crypt [libcrypt :refer :all]
                             [libbyte :refer :all])))

(defn run-all-tests-azjure []
  (run-all-tests #"net.ozias.crypt\..*\..*test.*"))
