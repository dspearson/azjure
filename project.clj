(defproject azjure "0.2.0-SNAPSHOT"
  :description "Encryption Library in Clojure"
  :url "https://github.com/CraZySacX/azjure"
  :license {:name "MIT"
            :url  "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/math.numeric-tower "0.0.4"]
                 [org.ozias.cljlibs/logging "0.1.5"]]
  :profiles {:dev {:source-paths
                    ["dev"]
                   :dependencies
                    [[org.clojars.jozias/midje "1.6.3"]
                     [org.clojure/tools.namespace "0.2.4"]
                     [org.ozias.cljlibs/scm "0.1.3"]]
                   :plugins
                    [[codox "0.8.0"]
                     [lein-midje "3.1.3"]
                     [org.ozias.plugins/lein-git-version "1.1.3"]]
                   :aliases
                    {"package"   ["do" "clean," "install"]
                     "slamhound" ["run" "-m" "slam.hound"]
                     "chk"       ["do"
                                  "archaic" "upgrade,"
                                  "slamhound" "src/,"
                                  "slamhound" "test/,"
                                  "eastwood" "{:namespaces [:source-paths]},"
                                  "kibit,"
                                  "check,"
                                  "bikeshed" "-v,"
                                  "midje"]
                     "most"      ["do" "clean," "doc," "chk," "package"]
                     "dep"       ["do" "deploy," "deploy" "clojars"]
                     "all"       ["do" "most," "dep"]}}}
  :jvm-opts ["-Xms1024m" "-Xmx1024m"]
  :deploy-repositories
  [["snapshots"
    {:url   "http://www.ozias.net/artifactory/libs-snapshot-local"
     :creds :gpg}]
   ["releases"
    {:url   "http://www.ozias.net/artifactory/libs-release-local"
     :creds :gpg}]]
  :scm {:name "git"
        :url  "https://github.com/CraZySacX/azjure"}
  :codox {:output-dir                "api"
          :exclude                   [azjure.version]
          :sources                   ["src" "test"]
          :src-dir-uri               "http://github.com/CraZySacX/azjure/blob/api-refactor/"
          :src-linenum-anchor-prefix "L"}
  :manifest {"Implementation-Version" "0.2.0-SNAPSHOT"}
  :git-version {:file {:assoc-in-keys [[:manifest "Implementation-Version"]]}})
