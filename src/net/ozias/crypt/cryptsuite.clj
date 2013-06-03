;; ## Crypt Suite Protocol
(ns ^{:author "Jason Ozias"} 
  net.ozias.crypt.cryptsuite
  (:require (net.ozias.crypt.cipher [blockcipher :as bc]
                                    [aes :refer (->Aes)]
                                    [blowfish :refer (->Blowfish)]
                                    [cast5 :refer (->CAST5)]
                                    [cast6 :refer (->CAST6)]
                                    [twofish :refer (->Twofish)])
            (net.ozias.crypt.mode [modeofoperation :as mode]
                                  [ecb :refer (->ElectronicCodebook)]
                                  [cbc :refer (->CipherBlockChaining)]
                                  [pcbc :refer (->PropagatingCipherBlockChaining)]
                                  [cfb :refer (->CipherFeedback)]
                                  [ofb :refer (->OutputFeedback)])
            (net.ozias.crypt.padding [pad :as padder]
                                     [pkcs7pad :refer (->PKCS7pad)]
                                     [zeropad :refer (->Zeropad)]
                                     [iso10126pad :refer (->ISO10126pad)]
                                     [x923pad :refer (->X923pad)]
                                     [iso7816pad :refer (->ISO7816pad)])))

;; ### CipherSuite
;; This protocol defines two functions
;;
;; #### encrypt
;; This function takes a cipher, mode, and padding
;; method, and uses that suite with the supplied
;; key and initialization vector to encrypt the
;; given byte array.
;;
;; #### decrypt
;; This function takes a cipher, mode, and padding
;; method, and uses that suite with the supplied
;; key and initialization vector to decrypt the
;; given words vector.
(defprotocol CryptSuite
  (encrypt [_ key iv bytearr])
  (decrypt [_ key iv words]))

;; #### PKCS7, Zeropad, ISO10126, X923, ISO7816
;; Setup the padding records
(def PKCS7 (->PKCS7pad))
(def Zeropad (->Zeropad))
(def ISO10126 (->ISO10126pad))
(def X923 (->X923pad))
(def ISO7816 (->ISO7816pad))

;; #### AES, Blowfish, CAST5, CAST6, Twofish
;; Setup the ciphers
(def AES (->Aes))
(def Blowfish (->Blowfish))
(def CAST5 (->CAST5))
(def CAST6 (->CAST6))
(def Twofish (->Twofish))

;; #### ECB,CBC,PCBC,CFB,OFB
;; Setup the mode for use in testing
(def ECB (->ElectronicCodebook))
(def CBC (->CipherBlockChaining))
(def PCBC (->PropagatingCipherBlockChaining))
(def CFB (->CipherFeedback))
(def OFB (->OutputFeedback))

;; ### encryptor
;; Helper function for encryption.  Pads the bytearr with the given padder
;; and then encrypts the array with the given cipher and mode.
;;
;; Evaluates to a vector of 32-bit words.
(defn- encryptor [[cipher mode padding] key iv bytev]
  (mode/encrypt mode cipher key iv (padder/pad padding bytev cipher)))

;; ### decryptor
;; Helper function for decryption.  Decrypts the given vector of words with
;; the cipher and mode given.  Then unpads the result with the given padder.
;;
;; Evaluates to an array of bytes.
(defn- decryptor [[cipher mode padding] key iv words]
  (padder/unpad padding (mode/decrypt mode cipher key iv words) cipher))

;; ### AESECBX
;; AES cipher, Electronic Codebook Mode, various padding methods
(defrecord AESECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES ECB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES ECB PKCS7] key iv words)))

(defrecord AESECBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES ECB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES ECB Zeropad] key iv words)))

(defrecord AESECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES ECB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES ECB ISO10126] key iv words)))

(defrecord AESECBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES ECB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES ECB X923] key iv words)))

(defrecord AESECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES ECB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES ECB ISO7816] key iv words)))

;; ### AESCBCX
;; AES cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord AESCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CBC PKCS7] key iv words)))

(defrecord AESCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CBC Zeropad] key iv words)))

(defrecord AESCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CBC ISO10126] key iv words)))

(defrecord AESCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CBC X923] key iv words)))

(defrecord AESCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CBC ISO7816] key iv words)))

;; ### AESPCBCX
;; AES cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord AESPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES PCBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES PCBC PKCS7] key iv words)))

(defrecord AESPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES PCBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES PCBC Zeropad] key iv words)))

(defrecord AESPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES PCBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES PCBC ISO10126] key iv words)))

(defrecord AESPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES PCBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES PCBC X923] key iv words)))

(defrecord AESPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES PCBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES PCBC ISO7816] key iv words)))

;; ### AESCFBX
;; AES cipher, Cipher Feedback Mode, various padding methods
(defrecord AESCFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CFB PKCS7] key iv words)))

(defrecord AESCFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CFB Zeropad] key iv words)))

(defrecord AESCFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CFB ISO10126] key iv words)))

(defrecord AESCFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CFB X923] key iv words)))

(defrecord AESCFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES CFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES CFB ISO7816] key iv words)))

;; ### AESOFBX
;; AES cipher, Output Feedback Mode, various padding methods
(defrecord AESOFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES OFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES OFB PKCS7] key iv words)))

(defrecord AESOFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES OFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES OFB Zeropad] key iv words)))

(defrecord AESOFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES OFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES OFB ISO10126] key iv words)))

(defrecord AESOFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES OFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES OFB X923] key iv words)))

(defrecord AESOFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [AES OFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [AES OFB ISO7816] key iv words)))

;; ### BFECBX
;; Blowfish cipher, Electronic Codebook Mode, various padding methods
(defrecord BFECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish ECB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish ECB PKCS7] key iv words)))

(defrecord BFECBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish ECB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish ECB Zeropad] key iv words)))

(defrecord BFECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish ECB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish ECB ISO10126] key iv words)))

(defrecord BFECBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish ECB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish ECB X923] key iv words)))

(defrecord BFECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish ECB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish ECB ISO7816] key iv words)))

;; ### BFCBCX
;; Blowfish cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord BFCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CBC PKCS7] key iv words)))

(defrecord BFCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CBC Zeropad] key iv words)))

(defrecord BFCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CBC ISO10126] key iv words)))

(defrecord BFCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CBC X923] key iv words)))

(defrecord BFCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CBC ISO7816] key iv words)))

;; ### BFPCBCX
;; Blowfish cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord BFPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish PCBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish PCBC PKCS7] key iv words)))

(defrecord BFPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish PCBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish PCBC Zeropad] key iv words)))

(defrecord BFPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish PCBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish PCBC ISO10126] key iv words)))

(defrecord BFPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish PCBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish PCBC X923] key iv words)))

(defrecord BFPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish PCBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish PCBC ISO7816] key iv words)))

;; ### BFCFBX
;; Blowfish cipher, Cipher Feedback Mode, various padding methods
(defrecord BFCFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CFB PKCS7] key iv words)))

(defrecord BFCFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CFB Zeropad] key iv words)))

(defrecord BFCFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CFB ISO10126] key iv words)))

(defrecord BFCFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CFB X923] key iv words)))

(defrecord BFCFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish CFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish CFB ISO7816] key iv words)))

;; ### BFOFBX
;; Blowfish cipher, Output Feedback Mode, various padding methods
(defrecord BFOFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish OFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish OFB PKCS7] key iv words)))

(defrecord BFOFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish OFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish OFB Zeropad] key iv words)))

(defrecord BFOFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish OFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish OFB ISO10126] key iv words)))

(defrecord BFOFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish OFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish OFB X923] key iv words)))

(defrecord BFOFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Blowfish OFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Blowfish OFB ISO7816] key iv words)))

;; ### CAST5ECBX
;; CAST5 cipher, Electronic Codebook Mode, various padding methods
(defrecord CAST5ECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 ECB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 ECB PKCS7] key iv words)))

(defrecord CAST5ECBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 ECB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 ECB Zeropad] key iv words)))

(defrecord CAST5ECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 ECB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 ECB ISO10126] key iv words)))

(defrecord CAST5ECBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 ECB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 ECB X923] key iv words)))

(defrecord CAST5ECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 ECB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 ECB ISO7816] key iv words)))

;; ### CAST5CBCX
;; CAST5 cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord CAST5CBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CBC PKCS7] key iv words)))

(defrecord CAST5CBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CBC Zeropad] key iv words)))

(defrecord CAST5CBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CBC ISO10126] key iv words)))

(defrecord CAST5CBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CBC X923] key iv words)))

(defrecord CAST5CBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CBC ISO7816] key iv words)))

;; ### CAST5PCBCX
;; CAST5 cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord CAST5PCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 PCBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 PCBC PKCS7] key iv words)))

(defrecord CAST5PCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 PCBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 PCBC Zeropad] key iv words)))

(defrecord CAST5PCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 PCBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 PCBC ISO10126] key iv words)))

(defrecord CAST5PCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 PCBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 PCBC X923] key iv words)))

(defrecord CAST5PCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 PCBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 PCBC ISO7816] key iv words)))

;; ### CAST5CFBX
;; CAST5 cipher, Cipher Feedback Mode, various padding methods
(defrecord CAST5CFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CFB PKCS7] key iv words)))

(defrecord CAST5CFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CFB Zeropad] key iv words)))

(defrecord CAST5CFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CFB ISO10126] key iv words)))

(defrecord CAST5CFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CFB X923] key iv words)))

(defrecord CAST5CFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 CFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 CFB ISO7816] key iv words)))

;; ### CAST5OFBX
;; CAST5 cipher, Output Feedback Mode, various padding methods
(defrecord CAST5OFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 OFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 OFB PKCS7] key iv words)))

(defrecord CAST5OFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 OFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 OFB Zeropad] key iv words)))

(defrecord CAST5OFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 OFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 OFB ISO10126] key iv words)))

(defrecord CAST5OFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 OFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 OFB X923] key iv words)))

(defrecord CAST5OFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST5 OFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST5 OFB ISO7816] key iv words)))

;; ### CAST6ECBX
;; CAST6 cipher, Electronic Codebook Mode, various padding methods
(defrecord CAST6ECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 ECB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 ECB PKCS7] key iv words)))

(defrecord CAST6ECBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 ECB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 ECB Zeropad] key iv words)))

(defrecord CAST6ECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 ECB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 ECB ISO10126] key iv words)))

(defrecord CAST6ECBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 ECB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 ECB X923] key iv words)))

(defrecord CAST6ECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 ECB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 ECB ISO7816] key iv words)))

;; ### CAST6CBCX
;; CAST6 cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord CAST6CBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CBC PKCS7] key iv words)))

(defrecord CAST6CBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CBC Zeropad] key iv words)))

(defrecord CAST6CBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CBC ISO10126] key iv words)))

(defrecord CAST6CBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CBC X923] key iv words)))

(defrecord CAST6CBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CBC ISO7816] key iv words)))

;; ### CAST6PCBCX
;; CAST6 cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord CAST6PCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 PCBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 PCBC PKCS7] key iv words)))

(defrecord CAST6PCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 PCBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 PCBC Zeropad] key iv words)))

(defrecord CAST6PCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 PCBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 PCBC ISO10126] key iv words)))

(defrecord CAST6PCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 PCBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 PCBC X923] key iv words)))

(defrecord CAST6PCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 PCBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 PCBC ISO7816] key iv words)))

;; ### CAST6CFBX
;; CAST6 cipher, Cipher Feedback Mode, various padding methods
(defrecord CAST6CFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CFB PKCS7] key iv words)))

(defrecord CAST6CFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CFB Zeropad] key iv words)))

(defrecord CAST6CFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CFB ISO10126] key iv words)))

(defrecord CAST6CFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CFB X923] key iv words)))

(defrecord CAST6CFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 CFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 CFB ISO7816] key iv words)))

;; ### CAST6OFBX
;; CAST6 cipher, Output Feedback Mode, various padding methods
(defrecord CAST6OFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 OFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 OFB PKCS7] key iv words)))

(defrecord CAST6OFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 OFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 OFB Zeropad] key iv words)))

(defrecord CAST6OFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 OFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 OFB ISO10126] key iv words)))

(defrecord CAST6OFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 OFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 OFB X923] key iv words)))

(defrecord CAST6OFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [CAST6 OFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [CAST6 OFB ISO7816] key iv words)))

;; ### TFECBX
;; Twofish cipher, Electronic Codebook Mode, various padding methods
(defrecord TFECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish ECB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish ECB PKCS7] key iv words)))

(defrecord TFECBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish ECB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish ECB Zeropad] key iv words)))

(defrecord TFECBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish ECB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish ECB ISO10126] key iv words)))

(defrecord TFECBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish ECB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish ECB X923] key iv words)))

(defrecord TFECBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish ECB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish ECB ISO7816] key iv words)))

;; ### TFCBCX
;; Twofish cipher, Cipher-Block Chaining Mode, various padding methods
(defrecord TFCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CBC PKCS7] key iv words)))

(defrecord TFCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CBC Zeropad] key iv words)))

(defrecord TFCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CBC ISO10126] key iv words)))

(defrecord TFCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CBC X923] key iv words)))

(defrecord TFCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CBC ISO7816] key iv words)))

;; ### TFPCBCX
;; Twofish cipher, Propagating Cipher-Block Chain Mode, various padding methods
(defrecord TFPCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish PCBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish PCBC PKCS7] key iv words)))

(defrecord TFPCBCZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish PCBC Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish PCBC Zeropad] key iv words)))

(defrecord TFPCBCISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish PCBC ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish PCBC ISO10126] key iv words)))

(defrecord TFPCBCX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish PCBC X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish PCBC X923] key iv words)))

(defrecord TFPCBCISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish PCBC ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish PCBC ISO7816] key iv words)))

;; ### TFCFBX
;; Twofish cipher, Cipher Feedback Mode, various padding methods
(defrecord TFCFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CFB PKCS7] key iv words)))

(defrecord TFCFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CFB Zeropad] key iv words)))

(defrecord TFCFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CFB ISO10126] key iv words)))

(defrecord TFCFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CFB X923] key iv words)))

(defrecord TFCFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish CFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish CFB ISO7816] key iv words)))

;; ### TFOFBX
;; Twofish cipher, Output Feedback Mode, various padding methods
(defrecord TFOFBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish OFB PKCS7] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish OFB PKCS7] key iv words)))

(defrecord TFOFBZERO []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish OFB Zeropad] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish OFB Zeropad] key iv words)))

(defrecord TFOFBISO10126 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish OFB ISO10126] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish OFB ISO10126] key iv words)))

(defrecord TFOFBX923 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish OFB X923] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish OFB X923] key iv words)))

(defrecord TFOFBISO7816 []
    CryptSuite
  (encrypt [_ key iv bytearr] (encryptor [Twofish OFB ISO7816] key iv bytearr))
  (decrypt [_ key iv words] (decryptor [Twofish OFB ISO7816] key iv words)))
