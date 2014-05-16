(ns azjure.cipher.testaes
  (require (azjure.cipher [cipher :refer :all]
                          [blockcipher :refer :all]
                          [aes :refer :all])
           (midje [config :as config]
                  [sweet :refer :all])))

(def ^{:private true :doc "Configuration Map"} cm
  (atom {}))

(def ^{:private true :doc "AES Spec 128-bit Plaintext"} aes-testpt
  [0 17 34 51 68 85 102 119 136 153 170 187 204 221 238 255])

(def ^{:private true :doc "AES Spec 128-bit Test Key"} aes-testkey-128
  [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
(def ^{:private true :doc "AES Spec 128-bit Key Ciphertext"} aes-testct-128
  [105 196 224 216 106 123 4 48 216 205 183 128 112 180 197 90])

(def ^{:private true :doc "AES Spec 192-bit Test Key"} aes-testkey-192
  [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23])
(def ^{:private true :doc "AES Spec 192-bit Key Ciphertext"} aes-testct-192
  [221 169 124 164 134 76 223 224 110 175 112 160 236 13 113 145])

(def ^{:private true :doc "AES Spec 256-bit Test Key"} aes-testkey-256
  [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16
   17 18 19 20 21 22 23 24 25 26 27 28 29 30 31])
(def ^{:private true :doc "AES Spec 256-bit Key Ciphertext"} aes-testct-256
  [142 162 183 202 81 103 69 191 234 252 73 144 75 73 96 137])

(config/at-print-level
  :print-facts
  (with-state-changes
    [(before :facts (swap! cm assoc :type :aes :key aes-testkey-128))]
    (facts
      "AES 128-bit Key\n========================================"
      (with-state-changes
        [(before :facts (swap! cm initialize))]
        (fact
          "AES Encryption"
          (encrypt-block @cm aes-testpt) => aes-testct-128)
        (fact
          "AES Decryption"
          (decrypt-block @cm aes-testct-128) => aes-testpt))))
  (with-state-changes
    [(before :facts (swap! cm assoc :key aes-testkey-192))]
    (facts
      "AES 192-bit Key\n========================================"
      (with-state-changes
        [(before :facts (swap! cm initialize))]
        (fact
          "AES Encryption"
          (encrypt-block @cm aes-testpt) => aes-testct-192)
        (fact
          "AES Decryption"
          (decrypt-block @cm aes-testct-192) => aes-testpt))))
  (with-state-changes
    [(before :facts (swap! cm assoc :key aes-testkey-256))]
    (facts
      "AES 256-bit Key\n========================================"
      (with-state-changes
        [(before :facts (swap! cm initialize))]
        (fact
          "AES Encryption"
          (encrypt-block @cm aes-testpt) => aes-testct-256)
        (fact
          "AES Decryption"
          (decrypt-block @cm aes-testct-256) => aes-testpt)))))