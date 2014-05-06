(ns org.azjure.libtest
  (:require [clojure.test :refer [is]]
            [org.azjure.cipher.blockcipher :as bc]
            [org.azjure.cipher.streamcipher :as sc]
            [org.azjure.cryptsuite :as cs]
            [org.azjure.testivs :refer :all]))

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

;; ### Stream Cipher testing helper function

(defn- ^{:doc "xor the given bytes with the generated keystream."} xor-bytes 
  [cipher initmap bytes]
  (mapv bit-xor bytes (sc/generate-keystream cipher initmap [0 (count bytes)])))

(defn ^{:doc "Test keystream encryption."} stream-encryptor
  [[cipher initmap plaintext ciphertext]]
  (is (= ciphertext (xor-bytes cipher initmap plaintext))))

(defn ^{:doc "Test keystream decryption."} stream-decryptor
  [[cipher initmap plaintext ciphertext]]
  (is (= plaintext (xor-bytes cipher initmap ciphertext))))
