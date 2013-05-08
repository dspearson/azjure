(defproject net.ozias.crypt/azjure "0.1.0-SNAPSHOT"
  :description "Encryption in Clojure"
  :url "http://www.ozias.net"
  :license {:name "GPLv3"
            :url "http://www.gnu.org/licenses/gpl.html"}
  :dependencies [[org.clojure/clojure "1.5.1"]]
  :aliases {"build" ["install"]}
  :jvm-opts ["-Xmx500m"]
  :plugins [[lein-marginalia "0.7.1"]]
  :repositories {"ozias.net" "http://www.ozias.net/archiva"})
