;; ## Crypt Suite Protocol
(ns ^{:author "Jason Ozias"} 
  org.azjure.cryptsuite
  (:require (org.azjure.cipher [blockcipher :as bc]
                               [aes :refer (->Aes)]
                               [blowfish :refer (->Blowfish)]
                               [twofish :refer (->Twofish)]
                               [cast5 :refer (->CAST5)]
                               [cast6 :refer (->CAST6)]
                               [tea :refer (->TEA)]
                               [xtea :refer (->XTEA)])
            (org.azjure.mode [modeofoperation :as mode]
                             [ecb :refer (->ElectronicCodebook)]
                             [cbc :refer (->CipherBlockChaining)]
                             [pcbc :refer (->PropagatingCipherBlockChaining)]
                             [cfb :refer (->CipherFeedback)]
                             [ofb :refer (->OutputFeedback)]
                             [ctr :refer (->CounterMode)])
            (org.azjure.padding [pad :as padder]
                                [pkcs7pad :refer (->PKCS7pad)]
                                [zeropad :refer (->Zeropad)]
                                [iso10126pad :refer (->ISO10126pad)]
                                [x923pad :refer (->X923pad)]
                                [iso7816pad :refer (->ISO7816pad)])))

;; ### CipherSuite
;; This protocol defines two functions
;;
;; #### encrypt
;; Encrypt the given bytes vector with the given
;; key and initialization vector.
;;
;; #### decrypt
;; Decrypt the given bytes vector with the given
;; key and initialization vector.
(defprotocol CryptSuite
  (encrypt [_ key iv bytes])
  (decrypt [_ key iv bytes]))

;; #### PKCS7, Zeropad, ISO10126, X923, ISO7816
;; Setup the padding records
(def PKCS7 (->PKCS7pad))
(def Zeropad (->Zeropad))
(def ISO10126 (->ISO10126pad))
(def X923 (->X923pad))
(def ISO7816 (->ISO7816pad))

;; #### AES, Blowfish, CAST5, CAST6, Twofish, TEA
;; Setup the ciphers
(def AES (->Aes))
(def Blowfish (->Blowfish))
(def Twofish (->Twofish))
(def CAST5 (->CAST5))
(def CAST6 (->CAST6))
(def TEA (->TEA))
(def XTEA (->XTEA))

;; #### ECB,CBC,PCBC,CFB,OFB,CTR
;; Setup the mode for use in testing
(def ECB (->ElectronicCodebook))
(def CBC (->CipherBlockChaining))
(def PCBC (->PropagatingCipherBlockChaining))
(def CFB (->CipherFeedback))
(def OFB (->OutputFeedback))
(def CTR (->CounterMode))

;; ### encryptor
;; Helper function for encryption.  Pads the bytearr with the given padder
;; and then encrypts the array with the given cipher and mode.
;;
;; Evaluates to a vector of bytes.
(defn- encryptor 
  ([cipher mode key iv bytes]
     (mode/encrypt mode cipher key iv bytes))
  ([cipher mode padding key iv bytes]
     (encryptor cipher mode key iv (padder/pad padding bytes cipher))))

;; ### decryptor
;; Helper function for decryption.  Decrypts the given vector of bytes with
;; the cipher and mode given.
;;
;; If a padding was supplied, unpads the result with the given padder.
;;
;; Evaluates to a vector of bytes.
(defn- decryptor 
  ([cipher mode key iv bytes]
     (mode/decrypt mode cipher key iv bytes))
  ([cipher mode padding key iv words]
     (padder/unpad padding (decryptor cipher mode key iv words))))

;; ### AESECBX
;; AES cipher, Electronic Codebook Mode, various padding methods
(defrecord AESECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES ECB PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES ECB PKCS7 key iv bytes)))

(defrecord AESECBZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES ECB Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES ECB Zeropad key iv bytes)))

(defrecord AESECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES ECB ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES ECB ISO10126 key iv bytes)))

(defrecord AESECBX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES ECB X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES ECB X923 key iv bytes)))

(defrecord AESECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES ECB ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES ECB ISO7816 key iv bytes)))

;; ### AESCBCX
;; AES cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord AESCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES CBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES CBC PKCS7 key iv bytes)))

(defrecord AESCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES CBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES CBC Zeropad key iv bytes)))

(defrecord AESCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES CBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES CBC ISO10126 key iv bytes)))

(defrecord AESCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES CBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES CBC X923 key iv bytes)))

(defrecord AESCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES CBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES CBC ISO7816 key iv bytes)))

;; ### AESPCBCX
;; AES cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord AESPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES PCBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES PCBC PKCS7 key iv bytes)))

(defrecord AESPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES PCBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES PCBC Zeropad key iv bytes)))

(defrecord AESPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES PCBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES PCBC ISO10126 key iv bytes)))

(defrecord AESPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES PCBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES PCBC X923 key iv bytes)))

(defrecord AESPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES PCBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES PCBC ISO7816 key iv bytes)))

;; ### AESCFB
;; AES cipher, Cipher Feedback Mode
(defrecord AESCFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES CFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES CFB key iv bytes)))

;; ### AESOFB
;; AES cipher, Output Feedback Mode
(defrecord AESOFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES OFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES OFB key iv bytes)))

;; ### AESCTR
;; AES cipher, Counter Mode
(defrecord AESCTR []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor AES CTR key iv bytes))
  (decrypt [_ key iv bytes] (decryptor AES CTR key iv bytes)))

;; ### BFECBX
;; Blowfish cipher, Electronic Codebook Mode, various padding methods
(defrecord BFECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish ECB PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish ECB PKCS7 key iv bytes)))

(defrecord BFECBZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish ECB Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish ECB Zeropad key iv bytes)))

(defrecord BFECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish ECB ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish ECB ISO10126 key iv bytes)))

(defrecord BFECBX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish ECB X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish ECB X923 key iv bytes)))

(defrecord BFECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish ECB ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish ECB ISO7816 key iv bytes)))

;; ### BFCBCX
;; Blowfish cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord BFCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish CBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish CBC PKCS7 key iv bytes)))

(defrecord BFCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish CBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish CBC Zeropad key iv bytes)))

(defrecord BFCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish CBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish CBC ISO10126 key iv bytes)))

(defrecord BFCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish CBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish CBC X923 key iv bytes)))

(defrecord BFCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish CBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish CBC ISO7816 key iv bytes)))

;; ### BFPCBCX
;; Blowfish cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord BFPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish PCBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish PCBC PKCS7 key iv bytes)))

(defrecord BFPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish PCBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish PCBC Zeropad key iv bytes)))

(defrecord BFPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish PCBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish PCBC ISO10126 key iv bytes)))

(defrecord BFPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish PCBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish PCBC X923 key iv bytes)))

(defrecord BFPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish PCBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish PCBC ISO7816 key iv bytes)))

;; ### BFCFBX
;; Blowfish cipher, Cipher Feedback Mode
(defrecord BFCFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish CFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish CFB key iv bytes)))

;; ### BFOFB
;; Blowfish cipher, Output Feedback Mode
(defrecord BFOFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish OFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish OFB key iv bytes)))

;; ### BFCTR
;; Blowfish cipher, Counter Mode
(defrecord BFCTR []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Blowfish CTR key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Blowfish CTR key iv bytes)))

;; ### CAST5ECBX
;; CAST5 cipher, Electronic Codebook Mode, various padding methods
(defrecord CAST5ECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 ECB PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 ECB PKCS7 key iv bytes)))

(defrecord CAST5ECBZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 ECB Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 ECB Zeropad key iv bytes)))

(defrecord CAST5ECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 ECB ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 ECB ISO10126 key iv bytes)))

(defrecord CAST5ECBX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 ECB X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 ECB X923 key iv bytes)))

(defrecord CAST5ECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 ECB ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 ECB ISO7816 key iv bytes)))

;; ### CAST5CBCX
;; CAST5 cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord CAST5CBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 CBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 CBC PKCS7 key iv bytes)))

(defrecord CAST5CBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 CBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 CBC Zeropad key iv bytes)))

(defrecord CAST5CBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 CBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 CBC ISO10126 key iv bytes)))

(defrecord CAST5CBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 CBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 CBC X923 key iv bytes)))

(defrecord CAST5CBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 CBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 CBC ISO7816 key iv bytes)))

;; ### CAST5PCBCX
;; CAST5 cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord CAST5PCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 PCBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 PCBC PKCS7 key iv bytes)))

(defrecord CAST5PCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 PCBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 PCBC Zeropad key iv bytes)))

(defrecord CAST5PCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 PCBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 PCBC ISO10126 key iv bytes)))

(defrecord CAST5PCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 PCBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 PCBC X923 key iv bytes)))

(defrecord CAST5PCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 PCBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 PCBC ISO7816 key iv bytes)))

;; ### CAST5CFB
;; CAST5 cipher, Cipher Feedback Mode
(defrecord CAST5CFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 CFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 CFB key iv bytes)))

;; ### CAST5OFB
;; CAST5 cipher, Output Feedback Mode
(defrecord CAST5OFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 OFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 OFB key iv bytes)))

;; ### CAST5CTR
;; CAST5 cipher, Counter Mode
(defrecord CAST5CTR []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST5 CTR key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST5 CTR key iv bytes)))

;; ### CAST6ECBX
;; CAST6 cipher, Electronic Codebook Mode, various padding methods
(defrecord CAST6ECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 ECB PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 ECB PKCS7 key iv bytes)))

(defrecord CAST6ECBZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 ECB Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 ECB Zeropad key iv bytes)))

(defrecord CAST6ECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 ECB ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 ECB ISO10126 key iv bytes)))

(defrecord CAST6ECBX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 ECB X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 ECB X923 key iv bytes)))

(defrecord CAST6ECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 ECB ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 ECB ISO7816 key iv bytes)))

;; ### CAST6CBCX
;; CAST6 cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord CAST6CBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 CBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 CBC PKCS7 key iv bytes)))

(defrecord CAST6CBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 CBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 CBC Zeropad key iv bytes)))

(defrecord CAST6CBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 CBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 CBC ISO10126 key iv bytes)))

(defrecord CAST6CBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 CBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 CBC X923 key iv bytes)))

(defrecord CAST6CBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 CBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 CBC ISO7816 key iv bytes)))

;; ### CAST6PCBCX
;; CAST6 cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord CAST6PCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 PCBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 PCBC PKCS7 key iv bytes)))

(defrecord CAST6PCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 PCBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 PCBC Zeropad key iv bytes)))

(defrecord CAST6PCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 PCBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 PCBC ISO10126 key iv bytes)))

(defrecord CAST6PCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 PCBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 PCBC X923 key iv bytes)))

(defrecord CAST6PCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 PCBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 PCBC ISO7816 key iv bytes)))

;; ### CAST6CFB
;; CAST6 cipher, Cipher Feedback Mode
(defrecord CAST6CFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 CFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 CFB key iv bytes)))

;; ### CAST6OFB
;; CAST6 cipher, Output Feedback Mode
(defrecord CAST6OFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 OFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 OFB key iv bytes)))

;; ### CAST6CTR
;; CAST6 cipher, Counter Mode
(defrecord CAST6CTR []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor CAST6 CTR key iv bytes))
  (decrypt [_ key iv bytes] (decryptor CAST6 CTR key iv bytes)))

;; ### TFECBX
;; Twofish cipher, Electronic Codebook Mode, various padding methods
(defrecord TFECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish ECB PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish ECB PKCS7 key iv bytes)))

(defrecord TFECBZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish ECB Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish ECB Zeropad key iv bytes)))

(defrecord TFECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish ECB ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish ECB ISO10126 key iv bytes)))

(defrecord TFECBX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish ECB X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish ECB X923 key iv bytes)))

(defrecord TFECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish ECB ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish ECB ISO7816 key iv bytes)))

;; ### TFCBCX
;; Twofish cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord TFCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish CBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish CBC PKCS7 key iv bytes)))

(defrecord TFCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish CBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish CBC Zeropad key iv bytes)))

(defrecord TFCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish CBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish CBC ISO10126 key iv bytes)))

(defrecord TFCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish CBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish CBC X923 key iv bytes)))

(defrecord TFCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish CBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish CBC ISO7816 key iv bytes)))

;; ### TFPCBCX
;; Twofish cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord TFPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish PCBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish PCBC PKCS7 key iv bytes)))

(defrecord TFPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish PCBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish PCBC Zeropad key iv bytes)))

(defrecord TFPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish PCBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish PCBC ISO10126 key iv bytes)))

(defrecord TFPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish PCBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish PCBC X923 key iv bytes)))

(defrecord TFPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish PCBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish PCBC ISO7816 key iv bytes)))

;; ### TFCFB
;; Twofish cipher, Cipher Feedback Mode
(defrecord TFCFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish CFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish CFB key iv bytes)))

;; ### TFOFB
;; Twofish cipher, Output Feedback Mode
(defrecord TFOFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish OFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish OFB key iv bytes)))

;; ### TFCTR
;; Twofish cipher, Counter Mode
(defrecord TFCTR []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor Twofish CTR key iv bytes))
  (decrypt [_ key iv bytes] (decryptor Twofish CTR key iv bytes)))

;; ### TEAECBX
;; TEA cipher, Electronic Codebook Mode, various padding methods
(defrecord TEAECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA ECB PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA ECB PKCS7 key iv bytes)))

(defrecord TEAECBZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA ECB Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA ECB Zeropad key iv bytes)))

(defrecord TEAECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA ECB ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA ECB ISO10126 key iv bytes)))

(defrecord TEAECBX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA ECB X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA ECB X923 key iv bytes)))

(defrecord TEAECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA ECB ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA ECB ISO7816 key iv bytes)))

;; ### TEACBCX
;; TEA cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord TEACBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA CBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA CBC PKCS7 key iv bytes)))

(defrecord TEACBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA CBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA CBC Zeropad key iv bytes)))

(defrecord TEACBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA CBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA CBC ISO10126 key iv bytes)))

(defrecord TEACBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA CBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA CBC X923 key iv bytes)))

(defrecord TEACBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA CBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA CBC ISO7816 key iv bytes)))

;; ### TEAPCBCX
;; TEA cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord TEAPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA PCBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA PCBC PKCS7 key iv bytes)))

(defrecord TEAPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA PCBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA PCBC Zeropad key iv bytes)))

(defrecord TEAPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA PCBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA PCBC ISO10126 key iv bytes)))

(defrecord TEAPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA PCBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA PCBC X923 key iv bytes)))

(defrecord TEAPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA PCBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA PCBC ISO7816 key iv bytes)))

;; ### TEACFB
;; TEA cipher, Cipher Feedback Mode
(defrecord TEACFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA CFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA CFB key iv bytes)))

;; ### TEAOFB
;; TEA cipher, Output Feedback Mode
(defrecord TEAOFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA OFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA OFB key iv bytes)))

;; ### TEACTR
;; TEA cipher, Counter Mode
(defrecord TEACTR []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor TEA CTR key iv bytes))
  (decrypt [_ key iv bytes] (decryptor TEA CTR key iv bytes)))

;; ### XTEAECBX
;; XTEA cipher, Electronic Codebook Mode, various padding methods
(defrecord XTEAECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA ECB PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA ECB PKCS7 key iv bytes)))

(defrecord XTEAECBZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA ECB Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA ECB Zeropad key iv bytes)))

(defrecord XTEAECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA ECB ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA ECB ISO10126 key iv bytes)))

(defrecord XTEAECBX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA ECB X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA ECB X923 key iv bytes)))

(defrecord XTEAECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA ECB ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA ECB ISO7816 key iv bytes)))

;; ### XTEACBCX
;; XTEA cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord XTEACBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA CBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA CBC PKCS7 key iv bytes)))

(defrecord XTEACBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA CBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA CBC Zeropad key iv bytes)))

(defrecord XTEACBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA CBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA CBC ISO10126 key iv bytes)))

(defrecord XTEACBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA CBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA CBC X923 key iv bytes)))

(defrecord XTEACBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA CBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA CBC ISO7816 key iv bytes)))

;; ### XTEAPCBCX
;; XTEA cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord XTEAPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA PCBC PKCS7 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA PCBC PKCS7 key iv bytes)))

(defrecord XTEAPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA PCBC Zeropad key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA PCBC Zeropad key iv bytes)))

(defrecord XTEAPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA PCBC ISO10126 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA PCBC ISO10126 key iv bytes)))

(defrecord XTEAPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA PCBC X923 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA PCBC X923 key iv bytes)))

(defrecord XTEAPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA PCBC ISO7816 key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA PCBC ISO7816 key iv bytes)))

;; ### XTEACFB
;; XTEA cipher, Cipher Feedback Mode
(defrecord XTEACFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA CFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA CFB key iv bytes)))

;; ### XTEAOFB
;; XTEA cipher, Output Feedback Mode
(defrecord XTEAOFB []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA OFB key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA OFB key iv bytes)))

;; ### XTEACTR
;; XTEA cipher, Counter Mode
(defrecord XTEACTR []
    CryptSuite
  (encrypt [_ key iv bytes] (encryptor XTEA CTR key iv bytes))
  (decrypt [_ key iv bytes] (decryptor XTEA CTR key iv bytes)))
