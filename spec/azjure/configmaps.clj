(ns azjure.configmaps)

(def ^{:doc "AES/ECB/ISO7816"} aesecbiso7816
  {:type :aes
   :mode :ecb
   :pad  :iso7816
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim
  {:type :aes
   :mode :cbc
   :pad  :x923
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim1
  {:type :aes
   :mode :cbc
   :pad  :x923
   :key  [0 1 2 3 4 5 6 7 7 8 10 11 12 13 14 15]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim2
  {:type :aes
   :mode :cbc
   :pad  :x923
   :eid  :str
   :doe  :str
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim3
  {:type :aes
   :mode :ecb
   :pad  :x923
   :eid  :str
   :eoe  :hex
   :did  :hex
   :doe  :str
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim4
  {:type :aes
   :mode :cbc
   :pad  :x923
   :eid  :str
   :eoe  :base64
   :did  :base64
   :doe  :str
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim5
  {:type :aes
   :mode :cbc
   :pad  :x923
   :eid  :str
   :eoe  :base64url
   :did  :base64url
   :doe  :str
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim6
  {:type :aes
   :mode :cbc
   :pad  :x923
   :eid  :base64
   :eoe  :hex
   :did  :hex
   :doe  :str
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim7
  {:type :aes
   :mode :ofb
   :pad  :x923
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim8
  {:type :aes
   :mode :cfb
   :pad  :x923
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim9
  {:type :aes
   :mode :pcbc
   :pad  :x923
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
(def aim10
  {:type :aes
   :mode :ctr
   :pad  :x923
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})