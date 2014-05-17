(ns azjure.testpadders
  (:require [azjure.padders :refer :all]
            [midje.config :as config]
            [midje.sweet :refer :all]))

(def ^{:private true :doc "Configuration Map"} cm (atom {}))

(defn- ranger
  "Generate a range vector from 0 to x - 1"
  [x]
  (vec (range x)))

(config/at-print-level
  :print-facts
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
            => (ranger 17))
      )))