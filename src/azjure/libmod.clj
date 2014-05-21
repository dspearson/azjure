(ns azjure.libmod)

(defn ^{:doc "x op y mod z"} modz [op z]
  (fn this
    ([] 0)
    ([x] x)
    ([x y] (mod (op x y) z))
    ([x y & more]
     (apply this (this x y) more))))

(def ^{:doc "x + y mod 8"} +mod8 (modz + 8))
(def ^{:doc "x + y mod 32"} +mod32 (modz + 32))
(def ^{:doc "x + y mod 2^32"} +modw (modz + 0x100000000))
(def ^{:doc "x - y mod 2^64"} +moddw (modz + 0x10000000000000000))
(def ^{:doc "x - y mod 512"} -mod512 (modz - 512))
(def ^{:doc "x - y mod 1024"} -mod1024 (modz - 1024))
(def ^{:doc "x - y mod 2^32"} -modw (modz - 0x100000000))
(def ^{:doc "x - y mod 2^64"} -moddw (modz - 0x10000000000000000))
(def ^{:doc "x * y mod 2^32"} *modw (modz * 0x100000000))