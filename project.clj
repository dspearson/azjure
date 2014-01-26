(defproject org.azjure/azjure "0.1.2-SNAPSHOT"
  :description "Encryption Library in Clojure"
  :url "https://github.com/CraZySacX/azjure"
  :license {:name "GPLv3"
            :url "http://www.gnu.org/licenses/gpl.html"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [org.clojure/math.numeric-tower "0.0.4"]
                 [com.taoensso/timbre "3.0.0-RC4"]]
  :profiles {:dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/tools.namespace "0.2.4"]]
                   :plugins [[codox "0.6.6"]]}
             :uberjar {:aot :all}}
  :aliases {"package" ["do" "clean," "uberjar"]
            "most" ["do" "clean," "doc," "package"]
            "dep" ["do" "deploy," "deploy" "clojars"]
            "all" ["do" "most," "dep"]}
  :jvm-opts ["-Xms1024m" "-Xmx1024m"]
  :deploy-repositories [["snapshots" 
                         {:url "http://www.ozias.net/artifactory/libs-snapshot-local"
                          :creds :gpg}]
                        ["releases"
                         {:url "http://www.ozias.net/artifactory/libs-release-local"
                          :creds :gpg}]]
  :scm {:name "git"
        :url "https://github.com/CraZySacX/azjure"}
  :codox {:output-dir "api"
          :exclude [leiningen.version]
          :sources ["src" "test"]
          :src-dir-uri "http://github.com/CraZySacX/azjure/blob/master/"
          :src-linenum-anchor-prefix "L"})
