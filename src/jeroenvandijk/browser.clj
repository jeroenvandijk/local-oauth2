(ns jeroenvandijk.browser
  (:require [clojure.java.shell]
            [clojure.java.browse]))


;; TODO support other operation systems than OS X
(defn- open-application
  [app-name & args]
  (let [cmd (cond-> ["open" "-na" app-name]
              args
              (-> (conj "--args")
                  (into args)))]
    (apply clojure.java.shell/sh cmd)))


(def browsers
  {:brave {:app "Brave browser"
           :incognito "--incognito"}

   :chrome {:app "Google chrome"
            :incognito "--incognito"}

   ;; See https://www.cyberciti.biz/faq/howto-run-firefox-from-the-command-line/
   :firefox {:app "Firefox"
             :incognito "--private-window"}})


(defn open
  [url & {:keys [incognito browser]}]
  (let [browser (or browser :chrome)
        incognito (or incognito false)

        {:keys [app] incognito-opt :incognito} (get browsers browser)]
    (if app
      (apply open-application app (if incognito [incognito-opt url] [url]))
      (clojure.java.browse/browse-url url))))
