(ns demo
  (:require [azjure.core :refer :all]
            [clojure.pprint :refer [pprint]]
            [clojure.repl :refer [source]]))

(def ^{:private true}
  encrypt-zeros (partial encrypt [0 0 0 0]))

(def ^{:private true}
  base-config-map
  {:type :aes :mode :ecb :pad :x923
   :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
   :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})

(def ^{:private true} config-map (atom base-config-map))

(def blah
  (encrypt [0 0 0 0]
           {:type :blowfish :mode :ecb :pad :x923
            :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
            :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]}))

(defn cipher-demo
  "### mode-demo
  Demonstrate each different implemented block cipher using ECB mode and
  ANSI x.923 padding"
  []
  (print "Demonstrate each different implemented block cipher using ECB mode ")
  (println "and ANSI x.923 padding")
  (print "Note the difference between each output when encrypting the same ")
  (println "input due to the different ciphers")
  (println)

  (println "AES:")
  (println "  Encrypt a vector of bytes with AES in ECB mode using ANSI X.923 ")
  (println "  padding.")
  (println "  Notice that the output is 5 bytes longer than the input as it ")
  (println "  has been padded to the block size of AES (16 bytes or 128 bits).")
  (println)
  (source blah)
  (println)
  (println "Output:")
  (print "  ")
  (println (encrypt-zeros @config-map))
  (println)

  (println "Blowfish:")
  (print "Encrypt a vector of bytes with Blowfish in ECB mode using ANSI X.923")
  (println " padding")
  (println)
  (println "Evaluating...")
  ;(source bfecbx923)
  (println)
  (println "Output:")
  ;(println (bfecbx923))
  (println)
  ; Encrypt a vector of bytes with AES in ECB mode using ANSI X.923 padding
  ;(encrypt [74 97 115 111 110 32 79 122 105 97 115]
  ;         {:type :blowfish :mode :ecb :pad :x923
  ;          :key  [0 0 0 0 0 0 0 0]
  ;          :iv   [0 0 0 0 0 0 0 0]})
  ;(encrypt [74 97 115 111 110 32 79 122 105 97 115]
  ;         {:type :cast6 :mode :ecb :pad :x923
  ;          :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
  ;          :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  ;(encrypt [74 97 115 111 110 32 79 122 105 97 115]
  ;         {:type :tea :mode :ecb :pad :x923
  ;          :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
  ;          :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  ;(encrypt [74 97 115 111 110 32 79 122 105 97 115]
  ;         {:type :xtea :mode :ecb :pad :x923
  ;          :key  [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
  ;          :iv   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
  )

(defn mode-demo
  "### mode-demo
  Demonstrate each different implemented block cipher mode using the Blowfish
  cipher and ANSI X.923 padding"
  []
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
            :iv   [0 0 0 0 0 0 0 0 0]}))

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

; Encrypt a string and encode the result as a hex string
(encrypt "Jason Ozias" {:type :blowfish :mode :ecb :pad :zero
                        :eid  :str :eoe :hex
                        :key  [0 0 0 0 0 0 0 0 0]
                        :iv   [0 0 0 0 0 0 0 0 0]})
(decrypt "926028b971d4a293b1421956828d773a"
         {:type :blowfish :mode :ecb :pad :zero
          :did  :hex :doe :str
          :key  [0 0 0 0 0 0 0 0 0]
          :iv   [0 0 0 0 0 0 0 0 0]})

(encrypt "Jason Ozias" {:type :blowfish :mode :ecb :pad :zero
                        :eid  :str :eoe :base32
                        :key  [0 0 0 0 0 0 0 0 0]
                        :iv   [0 0 0 0 0 0 0 0 0]})
(decrypt "SJQCROLR2SRJHMKCDFLIFDLXHI======"
         {:type :blowfish :mode :ecb :pad :zero
          :did  :base32 :doe :str
          :key  [0 0 0 0 0 0 0 0 0]
          :iv   [0 0 0 0 0 0 0 0 0]})


(encrypted-stream [74 97 115 111 110 32 79 122 105 97 115]
                  {:type  :salsa20
                   :key   [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
                   :nonce [0 0 0 0 0 0 0 0]})
