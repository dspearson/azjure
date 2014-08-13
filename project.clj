(defproject azjure "1.0.0-SNAPSHOT"
  :description "Encryption Library in Clojure"
  :url "https://github.com/CraZySacX/azjure"
  :license {:name "MIT"
            :url  "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/math.numeric-tower "0.0.4"]
                 [org.ozias.cljlibs/utils "0.1.7"]]
  :test-paths ["spec"]
  :profiles
  {:dev {:source-paths ["dev"]
         :dependencies [[org.clojure/tools.namespace "0.2.4"]
                        [org.ozias.cljlibs/scm "0.1.3"]
                        [org.clojars.jozias/speclj "3.0.2"]]
         :plugins      [[cider/cider-nrepl "0.7.0-SNAPSHOT"]
                        [lein-marginalia "0.7.1"]
                        [org.ozias.plugins/lein-git-version "1.1.3"]
                        [speclj "3.0.2"]]
         :aliases      {"package"   ["do" "clean," "install"]
                        "slamhound" ["run" "-m" "slam.hound"]
                        "doc"       ["marg" "-m" "-v" "0.2.0"]
                        "chk"       ["do"
                                     "archaic" "upgrade,"
                                     "slamhound" "src/,"
                                     "eastwood" "{:namespaces [:source-paths]},"
                                     "kibit,"
                                     "bikeshed" "-v,"
                                     "spec"]
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
  :manifest {"Implementation-Version" "0.2.0-SNAPSHOT"}
  :git-version {:file {:assoc-in-keys [[:manifest "Implementation-Version"]]}})
