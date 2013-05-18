;; ## Crypt Suite Protocol
(ns ^{:author "Jason Ozias"} 
  net.ozias.crypt.cryptsuite
  (:require [net.ozias.crypt.cipher.blockcipher :as bc]
            [net.ozias.crypt.mode.modeofoperation :as mode]
            [net.ozias.crypt.padding.pad :as padder]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.mode.ecb :refer (->ElectronicCodebook)]
            [net.ozias.crypt.mode.cbc :refer (->CipherBlockChaining)]
            [net.ozias.crypt.mode.pcbc :refer (->PropagatingCipherBlockChaining)]
            [net.ozias.crypt.mode.cfb :refer (->CipherFeedback)]
            [net.ozias.crypt.padding.pkcs7pad :refer (->PKCS7pad)]
            [net.ozias.crypt.padding.zeropad :refer (->Zeropad)]
            [net.ozias.crypt.padding.iso10126pad :refer (->ISO10126pad)]
            [net.ozias.crypt.padding.x923pad :refer (->X923pad)]
            [net.ozias.crypt.padding.iso7816pad :refer (->ISO7816pad)]))

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

;; #### AES, Blowfish
;; Setup the ciphers
(def AES (->Aes))
(def Blowfish (->Blowfish))

;; #### ECB,CBC,PCBC,CFB
;; Setup the mode for use in testing
(def ECB (->ElectronicCodebook))
(def CBC (->CipherBlockChaining))
(def PCBC (->PropagatingCipherBlockChaining))
(def CFB (->CipherFeedback))

;; ### encryptor
;; Helper function for encryption.  Pads the bytearr with the given padder
;; and then encrypts the array with the given cipher and mode.
;;
;; Evaluates to a vector of 32-bit words.
(defn- encryptor [[cipher mode padding] key iv bytearr]
  (mode/encrypt-blocks mode cipher iv (padder/pad padding bytearr cipher) key))

;; ### decryptor
;; Helper function for decryption.  Decrypts the given vector of words with
;; the cipher and mode given.  Then unpads the result with the given padder.
;;
;; Evaluates to an array of bytes.
(defn- decryptor [[cipher mode padding] key iv words]
  (padder/unpad padding (mode/decrypt-blocks mode cipher iv words key) cipher))

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
  (encrypt [_ key iv bytearr](encryptor [AES CFB Zeropad] key iv bytearr))
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
