(ns azjure.libtest
  (:require [clojure.data :refer [diff]]
            (azjure [core :refer :all]
                    [padders :refer :all])
            (azjure.cipher [aes :refer :all]
                           [blockcipher :refer :all]
                           [blowfish :refer :all]
                           [cast6 :refer :all]
                           [chacha :refer :all]
                           [cipher :refer :all]
                           [salsa20 :refer :all]
                           [streamcipher :refer :all]
                           [tea :refer :all]
                           [twofish :refer :all]
                           [xtea :refer :all])
            [speclj.core :refer :all]))

(def ^{:doc "64-bit vector of 0's"} zeros-64-bits (vec (take 8 (repeat 0))))

(def ^{:doc "128-bit vector of 0's"} zeros-128-bits (vec (take 16 (repeat 0))))

(def ^{:doc "Test plaintext"} pt "The quick brown fox jumped over the lazy dog")

(defn- rangerfn
  "Generate a range vector from 0 to x - 1"
  [x]
  (vec (range x)))

(def ^{:doc "Memoization of rangerfn"}
  rangev (memoize rangerfn))

(defn- has-xfix [xs ys take-fn]
  (if (empty? xs)
    true
    (= (take-fn (count xs) ys) xs)))

(defn- has-prefix [xs ys]
  (has-xfix xs ys take))

(defn- has-suffix [xs ys]
  (has-xfix xs ys take-last))

(defn check-blocksize
  "Check the blocksize"
  [cm x]
  (it "should report valid blocksize bits"
      (should= x (blocksize-bits cm))))

(defn check-keysizes
  "Check the keysizes"
  [cm s]
  (it "should report a valid range of keysizes"
      (should= s (keysizes-bits cm))))

(defn check-iv-size-bits
  "Check the IV (nonce) size supported by the given stream cipher"
  [cm x]
  (it "should report a valid IV (nonce) size"
      (should= x (iv-size-bits cm))))

(defn check-keystream-size-bytes
  "Check the keystream size (in bytes) supported by the given stream cipher"
  [cm x]
  (it "should report a valid keystream size"
      (should= x (keystream-size-bytes cm))))

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

(defn check-padder [cm test-blocks]
  (for [[pd ud unpadded padded] test-blocks]
    (if (= :iso10126 (:pad cm))
      (let [[prefix suffix] padded
            blah (pad cm unpadded)]
        (context
          "pad/unpad"
          (it pd (should (and (has-prefix prefix blah)
                              (has-suffix suffix blah))))
          (it ud (should= unpadded (unpad cm (pad cm unpadded))))))
      (context
        "pad/unpad"
        (it pd (should= padded (pad cm unpadded)))
        (it ud (should= unpadded (unpad cm padded)))))))