(ns demo
  (:require [azjure.core :refer :all]))

; Convert a string to a vector of bytes
(comment
  (vec (.getBytes "Jason Ozias"))
  )


(comment
  ; Encrypt a vector of bytes with <cipher>/ECB/X.923
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :aes :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :cast6 :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :tea :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :xtea :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})

  ; Encrypt a vector of bytes with Blowfish/<mode>/X.923
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :cbc :pad :x923
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :pcbc :pad :x923
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ofb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :cfb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ctr :pad :x923
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})

  ; Encrypt a vector of bytes with Blowfish/ECB/<padding>
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ecb :pad :iso7816
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ecb :pad :iso10126
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ecb :pad :pkcs7
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :blowfish :mode :ecb :pad :zero
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})

  ; Encrypt a string and encode the result in hex
  (encrypt "Jason Ozias" {:type :blowfish :mode :ecb :pad :zero
                          :eid :str :eoe :hex
                          :key  [0 0 0 0 0 0 0 0 0]
                          :iv   [0 0 0 0 0 0 0 0 0]})
  (decrypt "926028b971d4a293b1421956828d773a"
           {:type :blowfish :mode :ecb :pad :zero
            :did :hex :doe :str
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})

  (encrypt "Jason Ozias" {:type :blowfish :mode :ecb :pad :zero
                          :eid :str :eoe :base32
                          :key  [0 0 0 0 0 0 0 0 0]
                          :iv   [0 0 0 0 0 0 0 0 0]})
  (decrypt "SJQCROLR2SRJHMKCDFLIFDLXHI======"
           {:type :blowfish :mode :ecb :pad :zero
            :did :base32 :doe :str
            :key  [0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0]})


  (encrypted-stream [74 97 115 111 110 32 79 122 105 97 115]
                    {:type  :salsa20
                     :key   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                     :nonce [0 0 0 0 0 0 0 0]})
  )