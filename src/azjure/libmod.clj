(ns azjure.libmod
  "## libmod
  Modular math library"
  {:author "Jason Ozias"})

(defn modz
  "### modz

    x op y mod z"
  {:added "0.2.0"}
  [op z]
  (fn this
    ([] 0)
    ([x] x)
    ([x y] (mod (op x y) z))
    ([x y & more]
     (apply this (this x y) more))))

(def ^{:added "0.2.0"} +mod8
  "### +mod8
  x + y mod 8"
  (modz + 8))
(def ^{:added "0.2.0"} +mod32
  "### +mod32
  x + y mod 32"
  (modz + 32))
(def ^{:added "0.2.0"} +modw
  "### +modw
  x + y mod 2<sup>32</sup>"
  (modz + 0x100000000))
(def ^{:added "0.2.0"} +moddw
  "### +moddw
  x + y mod 2<sup>64</sup>"
  (modz + 0x10000000000000000))
(def ^{:added "0.2.0"} -mod512
  "### -mod512
  x - y mod 512"
  (modz - 512))
(def^{:added "0.2.0"}  -mod1024
  "### -mod1024
  x - y mod 1024"
  (modz - 1024))
(def ^{:added "0.2.0"} -modw
  "### -modw
  x - y mod 2<sup>32</sup>"
  (modz - 0x100000000))
(def ^{:added "0.2.0"} -moddw
  "### -moddw
  x - y mod 2<sup>64</sup>"
  (modz - 0x10000000000000000))
(def ^{:added "0.2.0"} *modw
  "### *modw
  x * y mod 2<sup>32</sup>"
  (modz * 0x100000000))