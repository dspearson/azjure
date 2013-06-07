(ns net.ozias.crypt.libtest
  (:require [clojure.test :refer (is)]
            (net.ozias.crypt [testivs :refer :all]
                             [testkeys :refer :all]
                             [cryptsuite :as cs])
            [net.ozias.crypt.cipher.blockcipher :as bc]))

(def ^{:doc "For type comparison"} array-of-bytes-type
  (Class/forName "[B")) 

;; ### Testing helper functions

(defn- ^{:doc "Is the given object a byte-array (type [B)"} byte-array?
  [obj]
  (= (type obj) array-of-bytes-type))

(defn- ^{:doc "Convert a vector of bytes to a bytearray"} b->barr 
  [bytes]
  (if (not (byte-array? bytes))
    (byte-array (mapv byte bytes))
    bytes))

;; ### Suite Testing helper functions

(defn ^{:doc "Helper function for suite encryption testing"} encryptor
  [[suite initmap pt ct] & {:keys [iv] :or {iv iv-128b}}]
  (is (= ct (cs/encrypt suite initmap iv (vec (.getBytes pt "UTF-8"))))))

(defn ^{:doc "Helper function for suite encryption testing"} decryptor
  [[suite initmap pt ct] & {:keys [iv] :or {iv iv-128b}}]
  (is (= pt (String. (b->barr (cs/decrypt suite initmap iv ct)) "UTF-8"))))

;; ### Block Cipher testing helper functions

(defn ^{:doc "Helper function for BlockCipher encryption testing"} encrypt-block 
  [[cipher initmap cleartext ciphertext]]
  (is (= ciphertext (bc/encrypt-block cipher cleartext initmap))))

(defn ^{:doc "Helper function for BlockCipher decryption testing"} decrypt-block
  [[cipher initmap plaintext ciphertext]]
  (is (= plaintext (bc/decrypt-block cipher ciphertext initmap))))
