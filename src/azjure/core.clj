(ns azjure.core
  "Encrypt/Decrypt API

  See https://github.com/CraZySacX/azjure for usage"
  {:author "Jason Ozias"}
  (:require [azjure.cipher.cipher :refer :all]
            [azjure.encoders :refer :all]
            [azjure.modes :refer :all]
            [azjure.padders :refer :all]))

(defn encrypt
  "Encrypt the given input i based on the configuration supplied in the map m"
  {:added "0.2.0"}
  [i m]
  (let [m (initialize m)]
    (->> (encryption-input-decoder m i)
         (pad m)
         (encrypt-blocks m)
         (encryption-output-encoder m))))

(defn decrypt
  "Encrypt the given input i based on the configuration supplied in the map m"
  {:added "0.2.0"}
  [i m]
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
               :key  [0 1 2 3 4 5 6 7 7 8 10 11 12 13 14 15]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim2 {:type :aes
               :mode :cbc
               :pad  :x923
               :eid  :str
               :doe  :str
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim3 {:type :aes
               :mode :ecb
               :pad  :x923
               :eid  :str
               :eoe  :hex
               :did  :hex
               :doe  :str
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim4 {:type :aes
               :mode :cbc
               :pad  :x923
               :eid  :str
               :eoe  :base64
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim5 {:type :aes
               :mode :cbc
               :pad  :x923
               :eid  :str
               :eoe  :base64url
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim6 {:type :aes
               :mode :cbc
               :pad  :x923
               :eid  :base64
               :eoe  :hex
               :did  :hex
               :doe  :str
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim7 {:type :aes
               :mode :ofb
               :pad  :x923
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim8 {:type :aes
               :mode :cfb
               :pad  :x923
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim9 {:type :aes
               :mode :pcbc
               :pad  :x923
               :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
               :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
    (def aim10 {:type :aes
                :mode :ctr
                :pad  :x923
                :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}))
  )