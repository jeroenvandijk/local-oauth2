(ns jeroenvandijk.local-oauth2.cli
  (:require [babashka.cli :as cli]
            [clojure.edn :as edn]
            [jeroenvandijk.local-oauth2.interface :as local-oauth2]
            [clojure.string :as str]))


(defn print-help [_]
  (println (str/trim "
Usage: token <subcommand> <options>

Subcommands:

access-token
 --label
 --scope
 --force

refresh-token
 --label
 --scope
 --force

list-tokens

remove-token <label>")))


(defn- tokens [{:keys [force label credential-file redirect-uri] :as opts}]
  (let [client-credentials (-> (slurp credential-file)
                               (edn/read-string)
                               (cond-> redirect-uri
                                 (assoc :redirect-uri redirect-uri)))]
    (cond (and force label)
          (do
            (local-oauth2/remove-cached-token label)
            (local-oauth2/load-or-request-token label
                                                client-credentials
                                                (assoc opts :prompt "consent")))

          force
          (local-oauth2/request-token client-credentials
                                      (assoc opts :prompt "consent"))


          label
          (local-oauth2/load-or-request-token label client-credentials opts)


          :else
          (local-oauth2/request-token client-credentials opts))))


(defn access-token [opts]
  (:access-token (tokens opts)))


(defn refresh-token
  "Not something you need in normal cases, but some client libs might need it"
  [opts]
  (:refresh-token (tokens (assoc opts
                                 :force true
                                 :access-type "offline"))))


(defn list-tokens [_]
  (->> (local-oauth2/list-cached-tokens)
       (map (fn [token] (str " * " token)))
       (clojure.string/join "\n")
       (println)))


(defn remove-token [{:keys [label]}]
  (local-oauth2/remove-cached-token label))


(def table
  [{:cmds ["access-token"]  :fn (comp println access-token :opts)}
   {:cmds ["refresh-token"] :fn (comp println refresh-token :opts)}
   {:cmds ["list-tokens"] :fn list-tokens}
   {:cmds ["remove-token"] :fn (comp remove-token :opts) :args->opts [:label]}
   {:cmds [] :fn print-help}])


(defn -main [& args]
  (cli/dispatch table args {;:require [:scope]
                            :coerce {:scope []}
                            :exec-args {:credential-file "client_credentials.edn"}}))


#?(:bb
   (apply -main *command-line-args*))

(comment


  (access-token {:scopes ["https://www.googleapis.com/auth/dfareporting"]})

  (refresh-token {:scopes ["https://www.googleapis.com/auth/dfareporting"]})


  )
