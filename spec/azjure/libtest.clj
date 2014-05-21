(ns azjure.libtest
  (:require [clojure.data :refer [diff]]
            [azjure.cipher.blockcipher :refer :all]
            [azjure.cipher.cipher :refer :all]
            [azjure.cipher.twofish :refer :all]
            [azjure.core :refer :all]
            [speclj.core :refer :all]))

(def ^{:doc "64-bit vector of 0's"} zeros-64-bits (vec (take 8 (repeat 0))))

(def ^{:doc "128-bit vector of 0's"} zeros-128-bits (vec (take 16 (repeat 0))))

(def ^{:doc "Test plaintext"} pt "The quick brown fox jumped over the lazy dog")

(defn check-blocksize
  "Check the blocksize"
  [cm x]
  (it "should report a blocksize of 128 bits"
      (should= x (blocksize-bits cm))))

(defn check-keysizes
  "Check the keysizes"
  [cm s]
  (it "should report a valid range of keysizes"
      (should= s (keysizes-bits cm))))

(defn check-test-vectors
  "Check the spec test vectors"
  [cm test-vectors]
  (for [[key cleartext ciphertext] test-vectors]
    (context
      "test vectors"
      (with lcm (initialize (assoc cm :key key)))

      (it "should encrypt to the proper ciphertext"
          (should= ciphertext (encrypt-block @lcm cleartext)))
      (it "should decrypt to the proper cleartext"
          (should= cleartext (decrypt-block @lcm ciphertext))))))

(defn check-test-suites
  "Check the test suites"
  [cm test-suites & {:keys [key iv] :or {key zeros-128-bits iv zeros-128-bits}}]
  (for [[mode pad ct] test-suites]
    (context
      "test suite"
      (with lcm (initialize (assoc cm :mode mode :pad pad :key key :iv iv)))

      (if (= pad :iso10126)
        (it "should encrypt to the proper ciphertext"
            (should= ct (last (diff ct (encrypt pt @lcm)))))
        (it "should encrypt to the proper ciphertext"
            (should= ct (encrypt pt @lcm)))))))