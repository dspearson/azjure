(ns ^{:author "Jason Ozias"}
  org.azjure.mode.testmode
  (:require [clojure.test :refer :all]
            (org.azjure [testkeys :refer :all]
                        [testivs :refer :all]
                        [testciphertext :refer :all]
                        [testplaintext :refer :all])
            (org.azjure.mode [modeofoperation :as mode]
                             [ecb :refer (->ElectronicCodebook)]
                             [cbc :refer (->CipherBlockChaining)]
                             [pcbc :refer (->PropagatingCipherBlockChaining)]
                             [cfb :refer (->CipherFeedback)]
                             [ofb :refer (->OutputFeedback)]
                             [ctr :refer (->CounterMode)])
            (org.azjure.cipher [cipher :as c]
                               [blockcipher :as bc]
                               [blowfish :refer (->Blowfish)]
                               [twofish :refer (->Twofish)])))

;; #### Modes
;; Setup the mode records for use in tests
(def ECB (->ElectronicCodebook))
(def CBC (->CipherBlockChaining))
(def PCBC (->PropagatingCipherBlockChaining))
(def CFB (->CipherFeedback))
(def OFB (->OutputFeedback))
(def CTR (->CounterMode))

;; #### Ciphers
;; Setup the cipher records for use in tests
(def BF (->Blowfish))
(def TF (->Twofish))

;; #### test-vectors
;; The mode test vectors 
(def test-vectors
  [[ECB  TF pt-1 tf-ecb ]
   [CBC  TF pt-1 tf-cbc ]
   [PCBC TF pt-1 tf-pcbc]
   [OFB  TF pt-1 tf-ofb ]
   [CFB  TF pt-1 tf-cfb ]])

(def ctr-test-vectors
  [[CTR  TF pt-1 tf-ctr]])

;; ## encrypt-blocks
;; Encrypt a vector of blocks.
(defn- encrypt-blocks [[mode cipher plaintext ciphertext] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (let [initmap (c/initialize cipher key)]
    (is (= ciphertext (mode/encrypt mode cipher initmap iv plaintext)))))

;; ## decrypt-blocks
;; Decrypt a vector of blocks.
(defn- decrypt-blocks [[mode cipher plaintext ciphertext] & {:keys [key iv] :or {key key-128b iv iv-128b}}]
  (let [initmap (c/initialize cipher key)]
    (is (= plaintext (mode/decrypt mode cipher initmap iv ciphertext)))))

;; ## testModes
;; Test the blockcipher modes
(deftest testModes
  (testing "Modes"
    (is (= true (every? true? (map encrypt-blocks test-vectors))))
    (is (= true (every? true? (map decrypt-blocks test-vectors))))
    (testing "CTR"
      (is (= true (every? true? (map #(encrypt-blocks % :iv iv-64b) ctr-test-vectors))))
      (is (= true (every? true? (map #(decrypt-blocks % :iv iv-64b) ctr-test-vectors)))))))
