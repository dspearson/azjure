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
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
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


  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :aes :mode :cbc :pad :x923
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  (encrypt [74 97 115 111 110 32 79 122 105 97 115]
           {:type :aes :mode :cbc :pad :x923
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  )