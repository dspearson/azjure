;; ## HC-256
;;
;; [HC256]: http://www3.ntu.edu.sg/home/wuhj/research/hc/hc256_fse.pdf
;; Designed to meet the [HC-256 Spec][HC256]
(ns org.azjure.cipher.hc256
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            (org.azjure [libcrypt :refer (to-hex)]
                        [libbyte :refer :all])))

(def ^{:doc "Used to store upper bounds and current keystreams
for initialized key/iv pairs"} hc256-key-streams
  (atom {}))

