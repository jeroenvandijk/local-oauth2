(ns jeroenvandijk.local-oauth2.impl
  (:require
   [babashka.fs :as fs]
   [babashka.http-client :as http]
   [cheshire.core :as json]
   [clojure.set :as set]
   [jeroenvandijk.browser :as browser]
   [org.httpkit.server :as server]
   [ring.util.codec :as codec])
  (:import
   [java.security SecureRandom]))


(defonce *port (atom 3000))
(defonce *app (atom nil))


(def app (fn [request]
           (if-let [handler @*app]
             (handler request)
             {:status 400
              :body "No app configured"})))


(defn initialize-server []
  (delay (server/run-server #'app {:port @*port})))


(defonce *server (initialize-server))


(defn stop-server []
  (@*server)
  (alter-var-root #'*server (constantly (initialize-server))))


(comment
  (stop-server)
  )


(defn set-port!
  "Sets port to something different than the default

   Only works if the server hasn't been started yet."
  [port]
  (when (not= @*port port)
    (if (realized? *server)
      (throw (ex-info "Cannot change port, server has already been started" {}))
      (reset! *port port))))


(defn- parse-params [params encoding]
  (let [params (codec/form-decode params encoding)]
    (if (map? params) params {})))


(defn receive-code-response [landing-uri response]
  (if landing-uri
    (let [landing-uri (if (= landing-uri :default)
                        "https://jeroenvandijk.github.io/local-oauth2/landing.html"
                        landing-uri)]
      {:status 302
       :headers {"Location" (str landing-uri "?" (codec/form-encode response))}})
    response))



(def ^:dynamic *code* (atom {:id :root
                             :prom (promise)}))


(defn set-receive-code-endpoint [state & {:keys [landing-uri]}]
  (let [**code *code*]
    (reset! *app (-> (fn [request]
                       (let [response
                             (case (:uri request)
                               "/"
                               (let [{state0 "state"
                                      :strs [code error] :as params}
                                     (some-> (:query-string request) (parse-params "UTF-8"))]
                                 (case error
                                   "access_denied"
                                   {:status 400
                                    :body "Request was cancelled"}

                                   nil
                                   (if (= state state0)
                                     (do (deliver (:prom @**code) code)
                                         {:status 200
                                          :body "Code received, you can close the window"})

                                     {:status 400
                                      :body (str "Invalid state " [params state state0])})

                                   {:status 500
                                    :body (str "Invalid state " [params state state0])}))

                               {:status 404
                                :body "Not found"})]
                         (receive-code-response landing-uri response)))))))


(defn open-auth-in-browser
  [{:keys [auth-uri client-id redirect-uri] :as _client-credentials}
   {:keys [scope state
           ;; optional
           access-type prompt login-hint browser-args]
    :or {access-type nil
         prompt nil
         login-hint nil
         browser-args nil}}]
  (assert (and auth-uri client-id redirect-uri))
  (browser/open
   (str auth-uri "?"
        (codec/form-encode
         (cond-> {:client_id     client-id
                  :redirect_uri  redirect-uri
                  :scope         (if (string? scope)
                                   scope
                                   (clojure.string/join " " scope))
                  :state         state
                  :response_type "code"}
           access-type (assoc :access_type access-type) #_#{"offline" "online"}
           prompt (assoc :prompt prompt) #_#{"consent" "select_account" "none"}
           login-hint (assoc :login_hint login-hint) #_"your-email@foo.com")))
   browser-args))


(defn handle-token-response [{:keys [status body] :as token-response}]
  (if (= status 200)
    (let [now (java.util.Date.)
          tokens (json/parse-string body true)]
      (-> tokens
          (dissoc :expires_in)
          (set/rename-keys {:access_token :access-token
                            :refresh_token :refresh-token})
          (assoc :received-at now
                 :expires-at (java.util.Date. (+ (.getTime now) (* (:expires_in tokens) 1000))))))
    (throw (ex-info "Unexpected token response: " body {:response token-response
                                                        :babashka/exit 1}))))


(defn get-access-token-via-code [{:keys [token-uri client-id client-secret redirect-uri]}
                                 {:keys [code]}]
  (assert token-uri)
  (handle-token-response
   (http/post token-uri
              {:headers {"Content-Type" "application/x-www-form-urlencoded"}
               :body (codec/form-encode {:code code
                                         :client_id client-id
                                         :client_secret client-secret
                                         :redirect_uri redirect-uri
                                         :grant_type "authorization_code"})})))


(def timeout-seconds 30)


(defn deref-code
  ([] (deref-code timeout-seconds))

  ([sum]
   ;; When running from the repl (clj, or babashka nrepl) `(System/getProperty "babashka.main")` is nil
   (let [code (deref (:prom @*code*) (* timeout-seconds 1000) ::timeout)]
     (if (= code ::timeout)
       (if (System/getProperty "babashka.main")
         (do (println "WARN: script has been waiting for" sum "seconds to receive the authentication code")
             ;; Try again, until it succeeds or user terminates script
             (deref-code (+ sum timeout-seconds)))

         ;; In repl mode we want an exception so we don't have to figure out what's happening
         (throw (ex-info (str "Waited" timeout-seconds "seconds to receive the authentication code")
                         {:code *code*})))
       code))))


(defn get-access-token
  [client-credentials opts]
  (get-access-token-via-code client-credentials (assoc opts :code (deref-code))))


(defn parse-redirect-uri [uri]
  (let [[_ prot host port path :as match] (some->> uri (re-matches #"(.+)://([^:]+)(?::([\d]+))?(.+)?"))
        error
        (cond
          (not match)
          (str "Excepted a redirect-uri of the form: http://localhost:<PORT_NUMBER>, got " (pr-str uri))

          (not= prot "http")
          (str "Expected http protocol, got " prot)

          (not (contains? #{"localhost" "127.0.0.1"} host))
          (str "Expected a localhost address, got " host)

          (not= path nil)
          (str "Expected path to be empty, got " path)

          (nil? port)
          (str "Expected a port number" path))]
    (if error
      (throw (ex-info error {}))
      {:port (Long/parseLong port)})))


(comment
  (parse-redirect-uri "http://localhost:3000"))


(defn request-token
  [{:keys [client-id client-secret redirect-uri landing-uri] :as client-credentials}
   {:keys [scope] :as opts}]
  (assert (and client-id client-secret redirect-uri) "Missing credentials")
  (assert scope "Missing scopes")
  (let [state (or (:state opts) (str (.nextLong (SecureRandom.))))
        {:keys [port]} (parse-redirect-uri redirect-uri)]
    (set-port! port)
    (force @*server)
    (binding [*code* (atom {:id state
                            :prom (promise)})]
      (set-receive-code-endpoint state {:landing-uri landing-uri})
      (open-auth-in-browser client-credentials (assoc opts :state state))
      (get-access-token client-credentials opts))))


(defn refresh-token [{:keys [token-uri client-id client-secret]} {:keys [refresh-token] :as token}]
  (assert (and token-uri client-id client-secret) "Missing credentials")
  (assert refresh-token "Token should contain refresh token")
  (let [new-token
        (handle-token-response
         (http/post token-uri
                    {:body (json/generate-string {:refresh_token refresh-token
                                                  :client_id client-id
                                                  :client_secret client-secret
                                                  :grant_type "refresh_token"})}))]
    (merge token new-token)))


(defn cached-tokens-dir []
  (let [xdg-base (if (System/getenv "XDG_DATA_HOME")
                   (fs/xdg-cache-home)
                   (str (System/getProperty "user.home") "/.local/share"))]
    (fs/file xdg-base "local-oauth2" "credentials")))


(defn cached-token-file [label]
  (fs/file (cached-tokens-dir) (str label ".edn")))


(defn load-cached-token [label]
  (let [token-file (cached-token-file label)]
    (when (fs/exists? token-file)
      (clojure.edn/read-string (slurp token-file)))))


(defn load-or-request-token [label client-credentials opts]
  (or (when-let [token (load-cached-token label)]
        (if (< (.getTime (java.util.Date.)) (- (.getTime (:expires-at token))
                                               1000))
          token
          (when (:refresh-token token)
            (let [new-token (refresh-token client-credentials token)]
              (merge token new-token)))))

      ;; Refresh
      (let [token (request-token client-credentials opts)
            token-file (cached-token-file label)]
        (fs/create-dirs (fs/parent token-file))
        (spit token-file (pr-str token))
        token)))


(defn list-cached-tokens []
  (mapv (fn [f] (-> (fs/file-name f)
                  (clojure.string/replace ".edn" "")))
        (sort (fs/list-dir (cached-tokens-dir)))))


(defn remove-cached-token [label]
  (let [token-file (cached-token-file label)]
    (when (fs/exists? token-file)
      (.delete token-file))))


(defn expire-cached-token [label]
  (let [token-file (cached-token-file label)]
    (if (fs/exists? token-file)
      (spit token-file (-> (slurp token-file)
                           (clojure.edn/read-string)
                           (assoc :expires-at (java.util.Date.))
                           (pr-str)))
      (throw (ex-info "File doesn't exist" {})))))
