(defproject org.azjure/azjure "0.1.0-SNAPSHOT"
  :description "Encryption Library in Clojure"
  :url "https://github.com/CraZySacX/azjure"
  :license {:name "GPLv3"
            :url "http://www.gnu.org/licenses/gpl.html"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [org.clojure/math.numeric-tower "0.0.2"]]
  :profiles {:dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/tools.namespace "0.2.3"]
                                  [com.taoensso/timbre "2.1.2"]]}}
  :target-path "target/"
  :aliases {"build" ["install"]
            "docs" ["do" "doc," "marg" "--multi" "src/" "test/"]}
  :jvm-opts ["-Xmx500m"]
  :plugins [[codox "0.6.4"]
            [lein-marginalia "0.7.1"]]
  :repositories [["snapshots" {:url "http://www.ozias.net/archiva/repository/snapshots/" :creds :gpg}]
                 ["releases" {:url "http://www.ozias.net/archiva/repository/internal/" :creds :gpg}]]
  :scm {:name "git"
         :url "https://github.com/CraZySacX/azjure"}
  :codox {:output-dir "api"
          :sources ["src" "test"]})
