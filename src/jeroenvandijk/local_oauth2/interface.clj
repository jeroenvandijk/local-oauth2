(ns jeroenvandijk.local-oauth2.interface
  (:require [jeroenvandijk.local-oauth2.impl :as impl]))


(defn request-token [client-credentials & {:as opts}]
  (impl/request-token client-credentials opts))


(defn refresh-token [client-credentials token]
  (impl/refresh-token client-credentials token))


(defn load-or-request-token [label client-credentials {:as opts}]
  (impl/load-or-request-token label client-credentials opts))


(defn list-cached-tokens []
  (impl/list-cached-tokens))


(defn load-cached-token [label]
  (impl/load-cached-token label))


(defn remove-cached-token [label]
  (impl/remove-cached-token label)) {}


(defn expire-cached-token [label]
  (impl/expire-cached-token label))


(defn stop-server []
  (impl/stop-server))
