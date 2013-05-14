(defproject net.ozias.crypt/azjure "0.1.0-SNAPSHOT"
  :description "Encryption Library in Clojure"
  :url "http://www.ozias.net"
  :license {:name "GPLv3"
            :url "http://www.gnu.org/licenses/gpl.html"}
  :dependencies [[org.clojure/clojure "1.5.1"]]
  :profiles {:dev {:dependencies [[org.clojure/tools.namespace "0.2.3"]]}}
  :aliases {"build" ["install"]
            "sdoc" ["marg" "--multi" "src/" "test/"]}
  :jvm-opts ["-Xmx500m"]
  :plugins [[lein-marginalia "0.7.1"]]
  :repositories {"ozias.net" "http://www.ozias.net/archiva"})
