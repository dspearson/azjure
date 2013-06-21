;; ## MICKEY 2.0
;;
;; [M2]: http://www.ecrypt.eu.org/stream/p3ciphers/mickey/mickey_p3.pdf
;; Designed to meet the [MICKEY 2.0 Spec][M2]
(ns org.azjure.cipher.mickey2
  (:require [clojure.math.numeric-tower :refer (expt)]
            (org.azjure.cipher [cipher :refer (Cipher)]
                               [streamcipher :refer [StreamCipher]])
            (org.azjure [libcrypt :refer :all]
                        [libbyte :refer :all])))
