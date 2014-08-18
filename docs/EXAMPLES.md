Examples
========
### Block Cipher Usage
#### Namespace(s)
```clojure
(:require ...
          [azjure.core :refer :all]
          [azjure.cipher.aes :refer :all] 
          ;Require all the cipher(s) you wish to use
          ...
          )
```
#### Encrypt\Decrypt
```clojure
;; Encrypt a vector of unsigned bytes with AES in ECB mode with PKCS7 padding
;; Note that the keys shown below are the required keys for a 
;; block cipher
(encrypt [0 0 0 0]
         {:type :aes :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to
;; [223 80 151 26 46 117 190 64 134 255 95 229 221 229 165 35]

;; Decrypt a vector of unsigned bytes with AES in ECB mode with PKCS7 padding
(decrypt [223 80 151 26 46 117 190 64 134 255 95 229 221 229 165 35]
         {:type :aes :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]

;; Encrypt a vector of unsigned bytes with Blowfish in ECB mode with PKCS7
;; padding
;; Note that the keys shown below are the required keys for a 
;; block cipher
(encrypt [0 0 0 0]
         {:type :blowfish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to (note the smaller blocksize of Blowfish)
;; [31 105 53 184 25 151 249 82]

;; Decrypt a vector of unsigned bytes with Blowfish in ECB mode with PKCS7
;; padding
(decrypt [31 105 53 184 25 151 249 82]
         {:type :blowfish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]

;; Encrypt a vector of unsigned bytes with CAST6 in ECB mode with PKCS7
;; padding
;; Note that the keys shown below are the required keys for a 
;; block cipher
(encrypt [0 0 0 0]
         {:type :cast6 :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to (note the smaller blocksize of Blowfish)
;; [81 161 66 105 73 70 105 156 142 94 216 0 227 174 44 69]

;; Decrypt a vector of unsigned bytes with CAST6 in ECB mode with PKCS7
;; padding
(decrypt [81 161 66 105 73 70 105 156 142 94 216 0 227 174 44 69]
         {:type :cast6 :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]

;; Encrypt a vector of unsigned bytes with Twofish in ECB mode with PKCS7
;; padding
;; Note that the keys shown below are the required keys for a 
;; block cipher
(encrypt [0 0 0 0]
         {:type :twofish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to (note the smaller blocksize of Blowfish)
;; [42 90 43 8 163 212 252 81 160 28 140 242 127 73 119 44]

;; Decrypt a vector of unsigned bytes with Twofish in ECB mode with PKCS7
;; padding
(decrypt [42 90 43 8 163 212 252 81 160 28 140 242 127 73 119 44]
         {:type :twofish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]

;; Encrypt a vector of unsigned bytes with TEA in ECB mode with PKCS7
;; padding
;; Note that the keys shown below are the required keys for a 
;; block cipher
(encrypt [0 0 0 0]
         {:type :tea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to (note the smaller blocksize of Blowfish)
;; [200 159 54 75 186 112 142 100]

;; Decrypt a vector of unsigned bytes with TEA in ECB mode with PKCS7
;; padding
(decrypt [200 159 54 75 186 112 142 100]
         {:type :tea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]

;; Encrypt a vector of unsigned bytes with XTEA in ECB mode with PKCS7
;; padding
;; Note that the keys shown below are the required keys for a 
;; block cipher
(encrypt [0 0 0 0]
         {:type :xtea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to (note the smaller blocksize of Blowfish)
;; [150 251 95 246 60 210 115 131]

;; Decrypt a vector of unsigned bytes with XTEA in ECB mode with PKCS7
;; padding
(decrypt [150 251 95 246 60 210 115 131]
         {:type :xtea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
;; Should evaluate to [0 0 0 0]
```