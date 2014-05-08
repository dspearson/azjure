(ns azjure.core
  (:require (azjure.cipher [cipher :refer :all]
                           [blockcipher :refer :all]
                           [streamcipher :refer :all])
            [azjure.encoders :refer :all]
            [azjure.modes :refer :all]
            [azjure.padders :refer :all]))

(defn encrypt [i m]
  (let [m (initialize m)]
    (->> (encryption-input-decoder m i)
         (pad m)
         (encrypt-blocks m)
         (encryption-output-encoder m))))

(defn decrypt [i m]
  (let [m (initialize m)]
    (->> (decryption-input-decoder m i)
         (decrypt-blocks m)
         (unpad m)
         (decryption-output-encoder m))))

(comment
  (do
    (def aim {:type :aes
              :mode :cbc
              :pad  :x923
              :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
              :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim1 {:type :aes
               :mode :cbc
               :pad  :x923
               :eid  :str
               :doe  :str
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim2 {:type :aes
               :mode :ecb
               :pad  :x923
               :eid  :str
               :eoe  :hex
               :did  :hex
               :doe  :str
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim3 {:type :aes
               :mode :cbc
               :pad  :x923
               :eid  :str
               :eoe  :base64
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim4 {:type :aes
               :mode :cbc
               :pad  :x923
               :eid  :str
               :eoe  :base64url
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}))
  )