(ns azjure.testpadders
  (:require [azjure.padders :refer :all]
            [midje.sweet :refer :all]))

(def ^{:private true :doc "Configuration Map"} cm (atom {}))

(defn- ranger
  "Generate a range vector from 0 to x - 1"
  [x]
  (vec (range x)))

(with-state-changes
  [(before :facts (swap! cm assoc :type :aes :pad :iso7816))]
  (facts
    "(pad :iso7816 x)\n========================================"
    (fact "pad 1 byte" (pad @cm (ranger 1))
          => [0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
    (fact "pad 2 bytes" (pad @cm (ranger 2))
          => [0 1 128 0 0 0 0 0 0 0 0 0 0 0 0 0])
    (fact "pad 3 bytes" (pad @cm (ranger 3))
          => [0 1 2 128 0 0 0 0 0 0 0 0 0 0 0 0])
    (fact "pad 15 bytes" (pad @cm (ranger 15))
          => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 128])
    (fact "pad 16 bytes" (pad @cm (ranger 16))
          => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
    (fact "pad 17 bytes" (pad @cm (ranger 17))
          => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
              16 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0]))
  (facts
    "(unpad :iso7816 x)\n========================================"
    (fact "unpad to 1 byte"
          (unpad @cm [0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
          => (ranger 1))
    (fact "unpad to 2 bytes"
          (unpad @cm [0 1 128 0 0 0 0 0 0 0 0 0 0 0 0 0])
          => (ranger 2))
    (fact "unpad to 3 bytes"
          (unpad @cm [0 1 2 128 0 0 0 0 0 0 0 0 0 0 0 0])
          => (ranger 3))
    (fact "unpad to 15 bytes"
          (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 128])
          => (ranger 15))
    (fact "unpad to 16 bytes"
          (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
          => (ranger 16))
    (fact "unpad to 17 bytes"
          (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                      16 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
          => (ranger 17)))
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :pkcs7))]
    (facts
      "(pad :pkcs7 x)\n========================================"
      (fact "pad 1 byte" (pad @cm (ranger 1))
            => [0 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15])
      (fact "pad 2 bytes" (pad @cm (ranger 2))
            => [0 1 14 14 14 14 14 14 14 14 14 14 14 14 14 14])
      (fact "pad 3 bytes" (pad @cm (ranger 3))
            => [0 1 2 13 13 13 13 13 13 13 13 13 13 13 13 13])
      (fact "pad 15 bytes" (pad @cm (ranger 15))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 1])
      (fact "pad 16 bytes" (pad @cm (ranger 16))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
      (fact "pad 17 bytes" (pad @cm (ranger 17))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                16 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15]))
    (facts
      "(unpad :pkcs7 x)\n========================================"
      (fact "unpad to 1 byte"
            (unpad @cm [0 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15])
            => (ranger 1))
      (fact "unpad to 2 bytes"
            (unpad @cm [0 1 14 14 14 14 14 14 14 14 14 14 14 14 14 14])
            => (ranger 2))
      (fact "unpad to 3 bytes"
            (unpad @cm [0 1 2 13 13 13 13 13 13 13 13 13 13 13 13 13])
            => (ranger 3))
      (fact "unpad to 15 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 1])
            => (ranger 15))
      (fact "unpad to 16 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
            => (ranger 16))
      (fact "unpad to 17 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                        16 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15])
            => (ranger 17))))
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :iso10126))]
    (facts
      "(pad :iso10126 x)\n========================================"
      (fact "pad 1 byte" (pad @cm (ranger 1))
            => (and (has-prefix [0]) (has-suffix [15])))
      (fact "pad 2 bytes" (pad @cm (ranger 2))
            => (and (has-prefix [0 1]) (has-suffix [14])))
      (fact "pad 3 bytes" (pad @cm (ranger 3))
            => (and (has-prefix [0 1 2]) (has-suffix [13])))
      (fact "pad 15 bytes" (pad @cm (ranger 15))
            => (and (has-prefix [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14])
                    (has-suffix [1])))
      (fact "pad 16 bytes" (pad @cm (ranger 16))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
      (fact "pad 17 bytes" (pad @cm (ranger 17))
            => (and (has-prefix [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
                    (has-suffix [15]))))
    (facts
      "(unpad :iso10126 x)\n========================================"
      (fact "unpad to 1 byte"
            (unpad @cm [0 200 100 101 15 15 15 15 15 15 15 15 15 15 15 15])
            => (ranger 1))
      (fact "unpad to 2 bytes"
            (unpad @cm [0 1 14 14 14 14 14 14 255 201 14 14 14 14 14 14])
            => (ranger 2))
      (fact "unpad to 3 bytes"
            (unpad @cm [0 1 2 13 123 13 13 173 13 133 113 13 13 13 13 13])
            => (ranger 3))
      (fact "unpad to 15 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 1])
            => (ranger 15))
      (fact "unpad to 16 bytes - only works if last byte value > blocksize"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 32])
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 32])
      (fact "unpad to 17 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                        16 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15])
            => (ranger 17))))
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :x923))]
    (facts
      "(pad :x923 x)\n========================================"
      (fact "pad 1 byte" (pad @cm (ranger 1))
            => [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 15])
      (fact "pad 2 bytes" (pad @cm (ranger 2))
            => [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 14])
      (fact "pad 3 bytes" (pad @cm (ranger 3))
            => [0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 13])
      (fact "pad 15 bytes" (pad @cm (ranger 15))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 1])
      (fact "pad 16 bytes" (pad @cm (ranger 16))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
      (fact "pad 17 bytes" (pad @cm (ranger 17))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                16 0 0 0 0 0 0 0 0 0 0 0 0 0 0 15]))
    (facts
      "(unpad :x923 x)\n========================================"
      (fact "unpad to 1 byte"
            (unpad @cm [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 15])
            => (ranger 1))
      (fact "unpad to 2 bytes"
            (unpad @cm [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 14])
            => (ranger 2))
      (fact "unpad to 3 bytes"
            (unpad @cm [0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 13])
            => (ranger 3))
      (fact "unpad to 15 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 1])
            => (ranger 15))
      (fact "unpad to 16 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
            => (ranger 16))
      (fact "unpad to 17 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                        16 0 0 0 0 0 0 0 0 0 0 0 0 0 0 15])
            => (ranger 17))))
  (with-state-changes
    [(before :facts (swap! cm assoc :pad :zero))]
    (facts
      "(pad :zero x)\n========================================"
      (fact "pad 1 byte - not reversible" (pad @cm (ranger 1))
            => [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
      (fact "pad 2 bytes" (pad @cm (ranger 2))
            => [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
      (fact "pad 3 bytes" (pad @cm (ranger 3))
            => [0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0])
      (fact "pad 15 bytes" (pad @cm (ranger 15))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 0])
      (fact "pad 16 bytes" (pad @cm (ranger 16))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
      (fact "pad 17 bytes" (pad @cm (ranger 17))
            => [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                16 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]))
    (facts
      "(unpad :zero x)\n========================================"
      (fact "unpad to 1 byte - reversed incorrectly"
            (unpad @cm [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
            => [])
      (fact "unpad to 2 bytes"
            (unpad @cm [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
            => (ranger 2))
      (fact "unpad to 3 bytes"
            (unpad @cm [0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0])
            => (ranger 3))
      (fact "unpad to 15 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 0])
            => (ranger 15))
      (fact "unpad to 16 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15])
            => (ranger 16))
      (fact "unpad to 17 bytes"
            (unpad @cm [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
                        16 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0])
            => (ranger 17)))))