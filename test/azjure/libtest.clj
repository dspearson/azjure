(ns azjure.libtest
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.core :refer :all]
            [azjure.ivs :refer [iv-128-zeros]]
            [azjure.keys :refer [key-128-zeros]]
            [azjure.plaintext :refer [pt]]
            [midje.sweet :refer :all]))

(defn check-blocksize-bits [cm v]
  (fact (blocksize-bits @cm) => v))

(defn check-keysizes-bits [cm v]
  (fact (keysizes-bits @cm) => v))

(defn check-test-vectors
  "Check the spec test vectors"
  [cm [key plaintext ciphertext]]
  (with-state-changes
    [(before :facts (swap! cm assoc :key key))]
    (facts
      (with-state-changes
        [(before :facts (swap! cm initialize))]
        (fact (encrypt-block @cm plaintext) => ciphertext)
        (fact (decrypt-block @cm ciphertext) => plaintext)))))

(defn check-test-suite
  "Check a mode pad combination"
  [cm [mode pad ciphertext]]
  (with-state-changes
    [(before :facts (swap! cm assoc
                           :mode mode
                           :pad pad
                           :key key-128-zeros
                           :iv iv-128-zeros))]
    (facts
      (if-not (= pad :iso10126)
        (fact (encrypt pt @cm) => ciphertext)
        (fact (encrypt pt @cm) => (has-prefix ciphertext)))
      (if-not (= pad :iso10126)
        (fact (decrypt ciphertext @cm) => pt)
        (fact (decrypt (encrypt pt @cm) @cm) => pt)))))