(ns net.ozias.crypt.libtest
  (:require [clojure.test :refer (is)]
            (net.ozias.crypt [testivs :refer :all]
                             [testkeys :refer :all]
                             [cryptsuite :as cs])
            [net.ozias.crypt.cipher.blockcipher :as bc]))

;; #### array-of-bytes-type
;; Used in byte-array? for comparison
(def array-of-bytes-type (Class/forName "[B")) 

;; ### byte-array?
;; Is the given object a byte-array (type [B)
(defn- byte-array? [obj]
  (= (type obj) array-of-bytes-type))

;; ### to-bytearray
;; Convert the given vector of bytes to a [B
;; if it is not already converted.
;;
;; Evaluates to a [B over the given byte vector
(defn- to-bytearray [bytes]
  (if (not (byte-array? bytes))
    (byte-array (mapv byte bytes))
    bytes))

;; ### bencryptor
;; Helper function for testing encryption
(defn bencryptor [[suite pt ct] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (is (= ct (cs/encrypt suite key iv pt))))

(defn encryptor [[suite pt ct] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (is (= ct (cs/encrypt suite key iv (vec (.getBytes pt "UTF-8"))))))

;; ### decryptor
;; Helper function for testing decryption
(defn bdecryptor [[suite pt ct] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (is (= pt (cs/decrypt suite key iv ct))))

(defn decryptor [[suite pt ct] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (is (= pt (String. (to-bytearray (cs/decrypt suite key iv ct)) "UTF-8"))))

;; ## encrypt-block
;; Helper function for BlockCipher encryption testing
(defn encrypt-block [[cipher initmap cleartext ciphertext]]
  (is (= ciphertext (bc/encrypt-block cipher cleartext initmap))))

;; ## decrypt-block
;; Helper function for BlockCipher decryption testing
(defn decrypt-block [[cipher initmap plaintext ciphertext]]
  (is (= plaintext (bc/decrypt-block cipher ciphertext initmap))))
