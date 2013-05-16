;; ## Crypt Suite Protocol
(ns ^{:author "Jason Ozias"} 
  net.ozias.crypt.cryptsuite
  (:require [net.ozias.crypt.cipher.blockcipher :as bc]
            [net.ozias.crypt.mode.modeofoperation :as mode]
            [net.ozias.crypt.padding.pad :as padder]
            [net.ozias.crypt.cipher.aes :refer (->Aes)]
            [net.ozias.crypt.cipher.blowfish :refer (->Blowfish)]
            [net.ozias.crypt.mode.cbc :refer (->CipherBlockChaining)]
            [net.ozias.crypt.mode.ecb :refer (->ElectronicCodebook)]
            [net.ozias.crypt.padding.pkcs7pad :refer (->PKCS7pad)]))

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

;; #### PKCS7
;; Setup the padding records for use in testing
(def PKCS7 (->PKCS7pad))

;; #### AES, Blowfish
;; Setup the ciphers for use in testing
(def AES (->Aes))
(def Blowfish (->Blowfish))

;; #### ECB,CBC
;; Setup the mode for use in testing
(def ECB (->ElectronicCodebook))
(def CBC (->CipherBlockChaining))

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

(defrecord AESECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr]
    (encryptor [AES ECB PKCS7] key iv bytearr))
  (decrypt [_ key iv words]
    (decryptor [AES ECB PKCS7] key iv words)))

(defrecord BFECBPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr]
    (encryptor [Blowfish ECB PKCS7] key iv bytearr))
  (decrypt [_ key iv words]
    (decryptor [Blowfish ECB PKCS7] key iv words)))

(defrecord AESCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr]
    (encryptor [AES CBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words]
    (decryptor [AES CBC PKCS7] key iv words)))

(defrecord BFCBCPKCS7 []
    CryptSuite
  (encrypt [_ key iv bytearr]
    (encryptor [Blowfish CBC PKCS7] key iv bytearr))
  (decrypt [_ key iv words]
    (decryptor [Blowfish CBC PKCS7] key iv words)))
