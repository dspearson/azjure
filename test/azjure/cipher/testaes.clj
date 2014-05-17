(ns azjure.cipher.testaes
  (:require [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.ciphertext :refer :all]
            [azjure.keys :refer :all]
            [azjure.plaintext :refer :all]
            [midje.sweet :refer :all]))

(def ^{:private true :doc "Configuration Map"} cm (atom {}))

(with-state-changes
  [(before :facts (swap! cm assoc :type :aes :key key-128-aes))]
  (facts
    "AES 128-bit Key\n========================================"
    (with-state-changes
      [(before :facts (swap! cm initialize))]
      (fact
        "AES Encryption"
        (encrypt-block @cm pt-128-aes) => ct-128-aes)
      (fact
        "AES Decryption"
        (decrypt-block @cm ct-128-aes) => pt-128-aes))))
(with-state-changes
  [(before :facts (swap! cm assoc :key key-192-aes))]
  (facts
    "AES 192-bit Key\n========================================"
    (with-state-changes
      [(before :facts (swap! cm initialize))]
      (fact
        "AES Encryption"
        (encrypt-block @cm pt-128-aes) => ct-192-aes)
      (fact
        "AES Decryption"
        (decrypt-block @cm ct-192-aes) => pt-128-aes))))
(with-state-changes
  [(before :facts (swap! cm assoc :key key-256-aes))]
  (facts
    "AES 256-bit Key\n========================================"
    (with-state-changes
      [(before :facts (swap! cm initialize))]
      (fact
        "AES Encryption"
        (encrypt-block @cm pt-128-aes) => ct-256-aes)
      (fact
        "AES Decryption"
        (decrypt-block @cm ct-256-aes) => pt-128-aes))))