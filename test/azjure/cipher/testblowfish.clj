(ns azjure.cipher.testblowfish
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.ciphertext :refer :all]
            [azjure.keys :refer :all]
            [azjure.plaintext :refer :all]
            [midje.sweet :refer :all]))

(def ^{:private true :doc "Configuration Map"} cm (atom {}))

(with-state-changes
  [(before :facts (swap! cm assoc :type :blowfish :key key-64-zeros))]
  (facts
    "Blowfish 1\n========================================"
    (with-state-changes
      [(before :facts (swap! cm initialize))]
      (fact "Encryption" (encrypt-block @cm pt-64-zeroes) => ct-64-bf1)
      (fact "Decryption" (decrypt-block @cm ct-64-bf1) => pt-64-zeroes))))
(with-state-changes
  [(before :facts (swap! cm assoc :key key-64-bf2))]
  (facts
    "Blowfish 2\n========================================"
    (with-state-changes
      [(before :facts (swap! cm initialize))]
      (fact "Encryption" (encrypt-block @cm pt-64-bf2) => ct-64-bf2)
      (fact "Decryption" (decrypt-block @cm ct-64-bf2) => pt-64-bf2))))
(with-state-changes
  [(before :facts (swap! cm assoc :key key-64-bf3))]
  (facts
    "Blowfish 3\n========================================"
    (with-state-changes
      [(before :facts (swap! cm initialize))]
      (fact "Encryption" (encrypt-block @cm pt-64-bf3) => ct-64-bf3)
      (fact "Decryption" (decrypt-block @cm ct-64-bf3) => pt-64-bf3))))
