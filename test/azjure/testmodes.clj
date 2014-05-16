(ns azjure.testmodes
  (require (azjure [modes :refer :all]
                   [padders :refer :all]
                   [configmaps :refer :all])
           (azjure.cipher [cipher :refer :all]
                          [aes :refer :all])
           (midje [config :as config]
                  [sweet :refer :all])))

(def cm (atom {}))

(config/at-print-level
  :print-facts
  (with-state-changes
    [(before :facts (swap! cm assoc
                           :type :aes
                           :mode :ecb
                           :pad :iso7816
                           :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                           :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]))]
    (facts
      "(encrypt-blocks :ecb m bv)\n========================================"
      (with-state-changes
        [(before :facts (swap! cm initialize))]
        (fact
          "AES/ECB/ISO7816 Encryption"
          (encrypt-blocks @cm (pad @cm [0]))
          => [185 112 223 190 64 105 138 241 99 143 227 139 211 223 59 47])
        (fact
          "AES/ECB/ISO7816 Decryption"
          (unpad
            @cm
            (decrypt-blocks
              @cm
              [185 112 223 190 64 105 138 241 99 143 227 139 211 223 59 47]))
          => [0])))))