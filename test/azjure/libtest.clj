(ns azjure.libtest
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.core :refer :all]))

(def ^{:doc "64-bit vector of 0's"} zeros-64-bits (vec (take 8 (repeat 0))))

(def ^{:doc "128-bit vector of 0's"} zeros-128-bits (vec (take 16 (repeat 0))))

(def ^{:doc "Test plaintext"} pt "The quick brown fox jumped over the lazy dog")

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
  [cm [mode pad ciphertext]
   & {:keys [key iv] :or {key zeros-128-bits iv zeros-128-bits}}]
  (with-state-changes
    [(before :facts (swap! cm assoc
                           :mode mode
                           :pad pad
                           :key key
                           :iv iv))]
    (facts
      (if-not (= pad :iso10126)
        (fact (encrypt pt @cm) => ciphertext)
        (fact (encrypt pt @cm) => (has-prefix ciphertext)))
      (if-not (= pad :iso10126)
        (fact (decrypt ciphertext @cm) => pt)
        (fact (decrypt (encrypt pt @cm) @cm) => pt)))))