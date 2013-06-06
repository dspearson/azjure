(ns net.ozias.crypt.libtest
  (:require [clojure.test :refer (is)]
            [net.ozias.crypt.cryptsuite :as cs]
            (net.ozias.crypt [testivs :refer :all]
                             [testkeys :refer :all])))

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

;; ### encryptor
;; Helper function for testing encryption
(defn encryptor [[suite pt ct] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (is (= ct (cs/encrypt suite key iv (vec (.getBytes pt "UTF-8"))))))

;; ### decryptor
;; Helper function for testing decryption
(defn decryptor [[suite pt ct] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (is (= pt (String. (to-bytearray (cs/decrypt suite key iv ct)) "UTF-8"))))
