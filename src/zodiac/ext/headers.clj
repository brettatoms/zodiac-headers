(ns zodiac.ext.headers
  "Zodiac extension for adding secure HTTP headers."
  (:require [clojure.string :as str]))

(create-ns 'zodiac.core)
(alias 'z 'zodiac.core)

;;; Presets

(def web
  "Headers for a standard web application."
  {:x-content-type-options "nosniff"
   :x-frame-options "DENY"
   :referrer-policy "strict-origin-when-cross-origin"
   :content-security-policy "default-src 'self'"
   :permissions-policy "geolocation=(), camera=(), microphone=()"
   :cross-origin-opener-policy "same-origin"})

(def secure-web
  "Headers for an HTTPS web application."
  (assoc web :strict-transport-security "max-age=63072000; includeSubDomains"))

(def api
  "Minimal headers for a JSON API server."
  {:x-content-type-options "nosniff"
   :referrer-policy "strict-origin-when-cross-origin"})

(def secure-api
  "Headers for an HTTPS API server."
  (assoc api :strict-transport-security "max-age=63072000; includeSubDomains"))

(def strict
  "Maximum security headers."
  {:x-content-type-options "nosniff"
   :x-frame-options "DENY"
   :referrer-policy "strict-origin-when-cross-origin"
   :strict-transport-security "max-age=63072000; includeSubDomains; preload"
   :content-security-policy "default-src 'self'"
   :permissions-policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
   :cross-origin-opener-policy "same-origin"
   :cross-origin-embedder-policy "require-corp"
   :cross-origin-resource-policy "same-origin"
   :x-permitted-cross-domain-policies "none"
   :server :remove
   :x-powered-by :remove})

;;; Implementation

(defn- header-name->str
  "Convert keyword or string to HTTP header string.
   :content-security-policy -> \"Content-Security-Policy\"
   \"content-security-policy\" -> \"Content-Security-Policy\"
   \"Content-Security-Policy\" -> \"Content-Security-Policy\""
  [k]
  (->> (str/split (name k) #"-")
       (map str/capitalize)
       (str/join "-")))

(defn wrap-headers
  "Ring middleware to add/remove security headers.

   Performance: Pre-builds transform function at init to minimize per-request work."
  [handler {:keys [add-headers remove-headers]}]
  (let [add-strs (when (seq add-headers)
                   (into {} (map (fn [[k v]] [(header-name->str k) v])) add-headers))
        remove-strs (when (seq remove-headers)
                      (into #{} (map header-name->str) remove-headers))
        ;; Pre-build the transform function based on what operations are needed
        transform-headers (cond
                            (and add-strs remove-strs)
                            (fn [headers]
                              (merge (reduce dissoc headers remove-strs) add-strs))

                            add-strs
                            (fn [headers]
                              (merge headers add-strs))

                            remove-strs
                            (fn [headers]
                              (reduce dissoc headers remove-strs))

                            :else
                            identity)]
    (fn [request]
      (when-let [response (handler request)]
        (update response :headers transform-headers)))))

(defn init
  "Initialize the headers extension.

   Options:
   - :headers - Map of header keywords to values. Use :remove as value
                to strip a header from responses. Default: web"
  ([] (init {}))
  ([{:keys [headers]
     :or {headers web}}]
   (let [{remove-headers true, add-headers false}
         (group-by #(= :remove (val %)) headers)]
     (fn [config]
       (update-in config [::z/app :user-middleware]
                  (fn [mw]
                    (cons [wrap-headers {:add-headers (into {} add-headers)
                                         :remove-headers (set (keys (into {} remove-headers)))}]
                          mw)))))))
