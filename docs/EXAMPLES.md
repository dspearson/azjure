# Examples
## Block Cipher Usage
### Namespace(s)
```clojure
(:require ...
          [azjure.core :refer :all]
          [azjure.cipher.aes :refer :all] 
          ;Require all the cipher(s) you wish to use
          ...
          )
```
### Encrypt\Decrypt
Change the cipher keep the mode and padding the same.  In each example, the
input argument for the decrypt is the value the encrypt function evaluated to.

#### AES/ECB/PKCS7
```clojure
(encrypt [0 0 0 0]
         {:type :aes :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})

(decrypt [223 80 151 26 46 117 190 64 134 255 95 229 221 229 165 35]
         {:type :aes :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
```

#### Blowfish/ECB/PKCS7
```clojure
(encrypt [0 0 0 0]
         {:type :blowfish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})

(decrypt [31 105 53 184 25 151 249 82]
         {:type :blowfish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
```

#### CAST6/ECB/PKCS7
```clojure
(encrypt [0 0 0 0]
         {:type :cast6 :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})

(decrypt [81 161 66 105 73 70 105 156 142 94 216 0 227 174 44 69]
         {:type :cast6 :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
```

#### Twofish/ECB/PKCS7
```clojure
(encrypt [0 0 0 0]
         {:type :twofish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})

(decrypt [42 90 43 8 163 212 252 81 160 28 140 242 127 73 119 44]
         {:type :twofish :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
```

#### TEA/ECB/PKCS7
```clojure
(encrypt [0 0 0 0]
         {:type :tea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})

(decrypt [200 159 54 75 186 112 142 100]
         {:type :tea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
```

#### XTEA/ECB/PKCS7
```clojure
(encrypt [0 0 0 0]
         {:type :xtea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
          
(decrypt [150 251 95 246 60 210 115 131]
         {:type :xtea :mode :ecb :pad :pkcs7
          :key [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
          :iv [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]})
```