(ns azjure.testcore
  (:require [azjure.ciphertext :refer :all]
            [azjure.core :refer :all]
            [azjure.ivs :refer :all]
            [azjure.keys :refer :all]
            [azjure.plaintext :refer :all]
            [midje.sweet :refer :all]))

(def ^{:private true :doc "Configuration Map"} cm
  (atom {:type :aes
         :mode :ecb
         :pad  :x923
         :eid  :str
         :doe  :str
         :key  key-128-zeros
         :iv   iv-128-zero}))

(facts
  "AES/ECB/X923"
  (fact "Encryption" (encrypt pt @cm) => ct-128-aesecbx923)
  (fact "Decryption" (decrypt ct-128-aesecbx923 @cm) => pt))
(facts
  "AES/ECB/ISO7816"
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :iso7816))]
    (fact "Encryption" (encrypt pt @cm) => ct-128-aesecbiso7816)
    (fact "Decryption" (decrypt ct-128-aesecbiso7816 @cm) => pt)))
(facts
  "AES/ECB/PKCS7"
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :pkcs7))]
    (fact "Encryption" (encrypt pt @cm) => ct-128-aesecbpkcs7)
    (fact "Decryption" (decrypt ct-128-aesecbpkcs7 @cm) => pt)))
(facts
  "AES/ECB/ZERO"
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :zero))]
    (fact "Encryption" (encrypt pt @cm) => ct-128-aesecbzero)
    (fact "Decryption" (decrypt ct-128-aesecbzero @cm) => pt)))
(facts
  "AES/ECB/ISO10126"
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :iso10126))]
    (fact "Encryption" (encrypt pt @cm) => (has-prefix ct-128-aesecb-base))
    (fact "Decryption" (decrypt (encrypt pt @cm) @cm) => pt)))

(with-state-changes
  [(before :facts (swap! cm assoc :mode :cbc :pad :x923))]
  (facts
    "AES/CBC/X923"
    (fact "Encryption" (encrypt pt @cm) => ct-128-aescbcx923)
    (fact "Decryption" (decrypt ct-128-aescbcx923 @cm) => pt))
  (facts
    "AES/CBC/ISO7816"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso7816))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aescbciso7816)
      (fact "Decryption" (decrypt ct-128-aescbciso7816 @cm) => pt)))
  (facts
    "AES/CBC/PKCS7"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :pkcs7))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aescbcpkcs7)
      (fact "Decryption" (decrypt ct-128-aescbcpkcs7 @cm) => pt)))
  (facts
    "AES/CBC/ZERO"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :zero))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aescbczero)
      (fact "Decryption" (decrypt ct-128-aescbczero @cm) => pt)))
  (facts
    "AES/CBC/ISO10126"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso10126))]
      (fact "Encryption" (encrypt pt @cm) => (has-prefix ct-128-aescbc-base))
      (fact "Decryption" (decrypt (encrypt pt @cm) @cm) => pt))))

(with-state-changes
  [(before :facts (swap! cm assoc :mode :pcbc :pad :x923))]
  (facts
    "AES/PCBC/X923"
    (fact "Encryption" (encrypt pt @cm) => ct-128-aespcbcx923)
    (fact "Decryption" (decrypt ct-128-aespcbcx923 @cm) => pt))
  (facts
    "AES/PCBC/ISO7816"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso7816))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aespcbciso7816)
      (fact "Decryption" (decrypt ct-128-aespcbciso7816 @cm) => pt)))
  (facts
    "AES/PCBC/PKCS7"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :pkcs7))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aespcbcpkcs7)
      (fact "Decryption" (decrypt ct-128-aespcbcpkcs7 @cm) => pt)))
  (facts
    "AES/PCBC/ZERO"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :zero))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aespcbczero)
      (fact "Decryption" (decrypt ct-128-aespcbczero @cm) => pt)))
  (facts
    "AES/PCBC/ISO10126"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso10126))]
      (fact "Encryption" (encrypt pt @cm) => (has-prefix ct-128-aespcbc-base))
      (fact "Decryption" (decrypt (encrypt pt @cm) @cm) => pt))))

(with-state-changes
  [(before :facts (swap! cm assoc :mode :cfb :pad :x923))]
  (facts
    "AES/CFB/X923"
    (fact "Encryption" (encrypt pt @cm) => ct-128-aescfbx923)
    (fact "Decryption" (decrypt ct-128-aescfbx923 @cm) => pt))
  (facts
    "AES/CFB/ISO7816"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso7816))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aescfbiso7816)
      (fact "Decryption" (decrypt ct-128-aescfbiso7816 @cm) => pt)))
  (facts
    "AES/CFB/PKCS7"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :pkcs7))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aescfbpkcs7)
      (fact "Decryption" (decrypt ct-128-aescfbpkcs7 @cm) => pt)))
  (facts
    "AES/CFB/ZERO"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :zero))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aescfbzero)
      (fact "Decryption" (decrypt ct-128-aescfbzero @cm) => pt)))
  (facts
    "AES/CFB/ISO10126"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso10126))]
      (fact "Encryption" (encrypt pt @cm) => (has-prefix ct-128-aescfb-base))
      (fact "Decryption" (decrypt (encrypt pt @cm) @cm) => pt))))

(with-state-changes
  [(before :facts (swap! cm assoc :mode :ofb :pad :x923))]
  (facts
    "AES/OFB/X923"
    (fact "Encryption" (encrypt pt @cm) => ct-128-aesofbx923)
    (fact "Decryption" (decrypt ct-128-aesofbx923 @cm) => pt))
  (facts
    "AES/OFB/ISO7816"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso7816))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aesofbiso7816)
      (fact "Decryption" (decrypt ct-128-aesofbiso7816 @cm) => pt)))
  (facts
    "AES/OFB/PKCS7"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :pkcs7))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aesofbpkcs7)
      (fact "Decryption" (decrypt ct-128-aesofbpkcs7 @cm) => pt)))
  (facts
    "AES/OFB/ZERO"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :zero))]
      (fact "Encryption" (encrypt pt @cm) => ct-128-aesofbzero)
      (fact "Decryption" (decrypt ct-128-aesofbzero @cm) => pt)))
  (facts
    "AES/OFB/ISO10126"
    (with-state-changes
      [(before :facts (swap! cm assoc :pad :iso10126))]
      (fact "Encryption" (encrypt pt @cm) => (has-prefix ct-128-aesofb-base))
      (fact "Decryption" (decrypt (encrypt pt @cm) @cm) => pt))))