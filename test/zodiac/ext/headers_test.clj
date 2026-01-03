(ns zodiac.ext.headers-test
  (:require [clojure.test :refer [deftest is testing]]
            [matcher-combinators.test :refer [match?]]
            [peridot.core :as peri]
            [zodiac.core :as z]
            [zodiac.ext.headers :as z.headers]))

;; ============================================================================
;; Test Helpers
;; ============================================================================

(defn test-client
  "Create a test client with the headers extension."
  [options]
  (-> {:start-server? false
       :cookie-secret "1234567890123456"}
      (merge options)
      z/start
      ::z/app))

(defn get-response-headers
  "Make a GET request and return the response headers."
  [app path]
  (-> (peri/session app)
      (peri/request path)
      :response
      :headers))

;; ============================================================================
;; Unit Tests: header-name->str
;; ============================================================================

(deftest header-name->str-test
  (testing "converts simple keyword header name"
    (is (= "Content-Type"
           (#'z.headers/header-name->str :content-type))))

  (testing "converts multi-word keyword header name"
    (is (= "Content-Security-Policy"
           (#'z.headers/header-name->str :content-security-policy))))

  (testing "converts single word keyword header name"
    (is (= "Server"
           (#'z.headers/header-name->str :server))))

  (testing "handles x-prefixed keyword headers"
    (is (= "X-Frame-Options"
           (#'z.headers/header-name->str :x-frame-options))))

  (testing "handles cross-origin keyword headers"
    (is (= "Cross-Origin-Opener-Policy"
           (#'z.headers/header-name->str :cross-origin-opener-policy))))

  (testing "converts lowercase string header name"
    (is (= "Content-Security-Policy"
           (#'z.headers/header-name->str "content-security-policy"))))

  (testing "normalizes already-capitalized string header name"
    (is (= "Content-Security-Policy"
           (#'z.headers/header-name->str "Content-Security-Policy"))))

  (testing "handles mixed-case string header name"
    (is (= "X-Frame-Options"
           (#'z.headers/header-name->str "x-Frame-options"))))

  (testing "handles single word string header name"
    (is (= "Server"
           (#'z.headers/header-name->str "server"))))

  (testing "handles empty string"
    (is (= ""
           (#'z.headers/header-name->str ""))))

  (testing "handles single character"
    (is (= "X"
           (#'z.headers/header-name->str "x"))))

  (testing "preserves hyphens in output"
    (is (= "X-Content-Type-Options"
           (#'z.headers/header-name->str "x-content-type-options")))))

;; ============================================================================
;; Unit Tests: Preset Definitions
;; ============================================================================

(deftest web-preset-test
  (testing "web preset contains expected headers"
    (is (match? {:x-content-type-options "nosniff"
                 :x-frame-options "DENY"
                 :referrer-policy "strict-origin-when-cross-origin"
                 :content-security-policy "default-src 'self'"
                 :permissions-policy string?
                 :cross-origin-opener-policy "same-origin"}
                z.headers/web)))

  (testing "web preset does not contain HSTS"
    (is (not (contains? z.headers/web :strict-transport-security)))))

(deftest secure-web-preset-test
  (testing "secure-web preset contains all web headers plus HSTS"
    (is (match? {:x-content-type-options "nosniff"
                 :x-frame-options "DENY"
                 :strict-transport-security #"max-age=\d+"}
                z.headers/secure-web)))

  (testing "secure-web includes includeSubDomains"
    (is (re-find #"includeSubDomains"
                 (:strict-transport-security z.headers/secure-web)))))

(deftest api-preset-test
  (testing "api preset is minimal"
    (is (= 2 (count z.headers/api))))

  (testing "api preset contains only essential headers"
    (is (match? {:x-content-type-options "nosniff"
                 :referrer-policy "strict-origin-when-cross-origin"}
                z.headers/api)))

  (testing "api preset does not contain frame options"
    (is (not (contains? z.headers/api :x-frame-options))))

  (testing "api preset does not contain CSP"
    (is (not (contains? z.headers/api :content-security-policy)))))

(deftest secure-api-preset-test
  (testing "secure-api preset contains api headers plus HSTS"
    (is (match? {:x-content-type-options "nosniff"
                 :referrer-policy "strict-origin-when-cross-origin"
                 :strict-transport-security string?}
                z.headers/secure-api))))

(deftest strict-preset-test
  (testing "strict preset contains maximum security headers"
    (is (match? {:x-content-type-options "nosniff"
                 :x-frame-options "DENY"
                 :referrer-policy "strict-origin-when-cross-origin"
                 :strict-transport-security #"preload"
                 :content-security-policy string?
                 :permissions-policy string?
                 :cross-origin-opener-policy "same-origin"
                 :cross-origin-embedder-policy "require-corp"
                 :cross-origin-resource-policy "same-origin"
                 :x-permitted-cross-domain-policies "none"
                 :server :remove
                 :x-powered-by :remove}
                z.headers/strict)))

  (testing "strict preset includes header removal"
    (is (= :remove (:server z.headers/strict)))
    (is (= :remove (:x-powered-by z.headers/strict)))))

;; ============================================================================
;; Unit Tests: Preset Composability
;; ============================================================================

(deftest preset-composability-test
  (testing "can add header to preset with assoc"
    (let [custom (assoc z.headers/web :strict-transport-security "max-age=31536000")]
      (is (contains? custom :strict-transport-security))
      (is (contains? custom :x-frame-options))))

  (testing "can remove header from preset with dissoc"
    (let [custom (dissoc z.headers/web :x-frame-options)]
      (is (not (contains? custom :x-frame-options)))
      (is (contains? custom :x-content-type-options))))

  (testing "can override header value with assoc"
    (let [custom (assoc z.headers/web :x-frame-options "SAMEORIGIN")]
      (is (= "SAMEORIGIN" (:x-frame-options custom)))))

  (testing "can merge presets"
    (let [custom (merge z.headers/api {:content-security-policy "default-src 'none'"})]
      (is (contains? custom :x-content-type-options))
      (is (= "default-src 'none'" (:content-security-policy custom)))))

  (testing "can build entirely custom headers"
    (let [custom {:x-content-type-options "nosniff"
                  :x-custom-header "custom-value"}]
      (is (= 2 (count custom))))))

;; ============================================================================
;; Integration Tests: Middleware Behavior
;; ============================================================================

(deftest wrap-headers-adds-headers-test
  (testing "middleware adds configured headers to response"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers z.headers/web})]})
          headers (get-response-headers app "/")]
      (is (= "nosniff" (get headers "X-Content-Type-Options")))
      (is (= "DENY" (get headers "X-Frame-Options")))
      (is (= "same-origin" (get headers "Cross-Origin-Opener-Policy"))))))

(deftest wrap-headers-removes-headers-test
  (testing "middleware removes headers marked with :remove"
    (let [handler (fn [_] {:status 200
                           :headers {"Server" "Jetty"
                                     "X-Powered-By" "Clojure"}
                           :body "ok"})
          app (test-client {:routes ["/" handler]
                            :extensions [(z.headers/init {:headers {:server :remove
                                                                    :x-powered-by :remove}})]})
          headers (get-response-headers app "/")]
      (is (not (contains? headers "Server")))
      (is (not (contains? headers "X-Powered-By"))))))

(deftest wrap-headers-mixed-add-remove-test
  (testing "middleware can add and remove headers simultaneously"
    (let [handler (fn [_] {:status 200
                           :headers {"Server" "Jetty"}
                           :body "ok"})
          app (test-client {:routes ["/" handler]
                            :extensions [(z.headers/init {:headers {:x-content-type-options "nosniff"
                                                                    :server :remove}})]})
          headers (get-response-headers app "/")]
      (is (= "nosniff" (get headers "X-Content-Type-Options")))
      (is (not (contains? headers "Server"))))))

(deftest wrap-headers-preserves-existing-headers-test
  (testing "middleware preserves headers set by handler"
    (let [handler (fn [_] {:status 200
                           :headers {"X-Custom" "value"
                                     "Content-Type" "text/plain"}
                           :body "ok"})
          app (test-client {:routes ["/" handler]
                            :extensions [(z.headers/init {:headers z.headers/api})]})
          headers (get-response-headers app "/")]
      (is (= "value" (get headers "X-Custom")))
      (is (= "text/plain" (get headers "Content-Type")))
      (is (= "nosniff" (get headers "X-Content-Type-Options"))))))

(deftest wrap-headers-overrides-handler-headers-test
  (testing "security headers override handler-set values"
    (let [handler (fn [_] {:status 200
                           :headers {"X-Frame-Options" "ALLOWALL"}
                           :body "ok"})
          app (test-client {:routes ["/" handler]
                            :extensions [(z.headers/init {:headers {:x-frame-options "DENY"}})]})
          headers (get-response-headers app "/")]
      (is (= "DENY" (get headers "X-Frame-Options"))))))

;; ============================================================================
;; Integration Tests: Nil Response Handling
;; ============================================================================

(deftest wrap-headers-nil-response-test
  (testing "middleware handles nil response gracefully"
    (let [app (test-client {:routes ["/" (constantly nil)]
                            :extensions [(z.headers/init {:headers z.headers/web})]})
          response (-> (peri/session app)
                       (peri/request "/")
                       :response)]
      ;; When handler returns nil, Zodiac/router returns a 406 Not Acceptable
      ;; The headers middleware should still apply headers to this response
      (is (some? response))
      (is (= 406 (:status response)))
      (is (= "nosniff" (get-in response [:headers "X-Content-Type-Options"]))))))

;; ============================================================================
;; Integration Tests: Init Function
;; ============================================================================

(deftest init-default-headers-test
  (testing "init uses web preset by default"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init)]})
          headers (get-response-headers app "/")]
      (is (= "nosniff" (get headers "X-Content-Type-Options")))
      (is (= "DENY" (get headers "X-Frame-Options"))))))

(deftest init-custom-headers-test
  (testing "init accepts custom headers map"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers {:x-custom "value"}})]})
          headers (get-response-headers app "/")]
      (is (= "value" (get headers "X-Custom")))
      (is (not (contains? headers "X-Frame-Options"))))))

(deftest init-empty-headers-test
  (testing "init with empty headers adds no security headers"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers {}})]})
          headers (get-response-headers app "/")]
      (is (not (contains? headers "X-Content-Type-Options")))
      (is (not (contains? headers "X-Frame-Options"))))))

(deftest init-returns-function-test
  (testing "init returns a function"
    (is (fn? (z.headers/init))))

  (testing "init with options returns a function"
    (is (fn? (z.headers/init {:headers z.headers/api})))))

(deftest init-config-transformation-test
  (testing "init function transforms config correctly"
    (let [init-fn (z.headers/init {:headers z.headers/web})
          config (init-fn {:zodiac.core/app {:user-middleware []}})]
      (is (seq (get-in config [:zodiac.core/app :user-middleware]))))))

;; ============================================================================
;; Integration Tests: All Presets with Real Requests
;; ============================================================================

(deftest all-presets-integration-test
  (testing "web preset headers in real request"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers z.headers/web})]})
          headers (get-response-headers app "/")]
      (is (= "nosniff" (get headers "X-Content-Type-Options")))
      (is (= "DENY" (get headers "X-Frame-Options")))
      (is (= "strict-origin-when-cross-origin" (get headers "Referrer-Policy")))
      (is (= "default-src 'self'" (get headers "Content-Security-Policy")))
      (is (some? (get headers "Permissions-Policy")))
      (is (= "same-origin" (get headers "Cross-Origin-Opener-Policy")))))

  (testing "secure-web preset headers in real request"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers z.headers/secure-web})]})
          headers (get-response-headers app "/")]
      (is (some? (get headers "Strict-Transport-Security")))
      (is (re-find #"max-age=" (get headers "Strict-Transport-Security")))))

  (testing "api preset headers in real request"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers z.headers/api})]})
          headers (get-response-headers app "/")]
      (is (= "nosniff" (get headers "X-Content-Type-Options")))
      (is (= "strict-origin-when-cross-origin" (get headers "Referrer-Policy")))
      (is (not (contains? headers "X-Frame-Options")))
      (is (not (contains? headers "Content-Security-Policy")))))

  (testing "secure-api preset headers in real request"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers z.headers/secure-api})]})
          headers (get-response-headers app "/")]
      (is (some? (get headers "Strict-Transport-Security")))))

  (testing "strict preset headers in real request"
    (let [handler (fn [_] {:status 200
                           :headers {"Server" "Test"
                                     "X-Powered-By" "Clojure"}
                           :body "ok"})
          app (test-client {:routes ["/" handler]
                            :extensions [(z.headers/init {:headers z.headers/strict})]})
          headers (get-response-headers app "/")]
      (is (= "nosniff" (get headers "X-Content-Type-Options")))
      (is (= "DENY" (get headers "X-Frame-Options")))
      (is (re-find #"preload" (get headers "Strict-Transport-Security")))
      (is (= "require-corp" (get headers "Cross-Origin-Embedder-Policy")))
      (is (= "same-origin" (get headers "Cross-Origin-Resource-Policy")))
      (is (= "none" (get headers "X-Permitted-Cross-Domain-Policies")))
      (is (not (contains? headers "Server")))
      (is (not (contains? headers "X-Powered-By"))))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest multiple-routes-test
  (testing "headers applied to all routes"
    (let [app (test-client {:routes [["/" (constantly {:status 200 :body "home"})]
                                     ["/api" (constantly {:status 200 :body "api"})]]
                            :extensions [(z.headers/init {:headers z.headers/web})]})
          home-headers (get-response-headers app "/")
          api-headers (get-response-headers app "/api")]
      (is (= "nosniff" (get home-headers "X-Content-Type-Options")))
      (is (= "nosniff" (get api-headers "X-Content-Type-Options"))))))

(deftest json-response-headers-test
  (testing "headers applied to JSON responses"
    (let [app (test-client {:routes ["/" (constantly {:status 200
                                                      :headers {"Content-Type" "application/json"}
                                                      :body "{\"ok\":true}"})]
                            :extensions [(z.headers/init {:headers z.headers/api})]})
          headers (get-response-headers app "/")]
      (is (= "nosniff" (get headers "X-Content-Type-Options")))
      (is (= "application/json" (get headers "Content-Type"))))))

(deftest redirect-response-headers-test
  (testing "headers applied to redirect responses"
    (let [app (test-client {:routes ["/" (constantly {:status 302
                                                      :headers {"Location" "/other"}
                                                      :body ""})]
                            :extensions [(z.headers/init {:headers z.headers/web})]})
          response (-> (peri/session app)
                       (peri/request "/")
                       :response)]
      (is (= 302 (:status response)))
      (is (= "nosniff" (get-in response [:headers "X-Content-Type-Options"]))))))

(deftest error-response-headers-test
  (testing "headers applied to error responses"
    (let [app (test-client {:routes ["/" (constantly {:status 500 :body "error"})]
                            :extensions [(z.headers/init {:headers z.headers/web})]})
          response (-> (peri/session app)
                       (peri/request "/")
                       :response)]
      (is (= 500 (:status response)))
      (is (= "nosniff" (get-in response [:headers "X-Content-Type-Options"]))))))

(deftest case-sensitivity-test
  (testing "keyword header names are properly capitalized"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers {:x-content-type-options "nosniff"
                                                                    :strict-transport-security "max-age=123"}})]})
          headers (get-response-headers app "/")]
      ;; Headers should be Title-Case
      (is (contains? headers "X-Content-Type-Options"))
      (is (contains? headers "Strict-Transport-Security"))
      ;; Not lowercase
      (is (not (contains? headers "x-content-type-options")))
      (is (not (contains? headers "strict-transport-security"))))))

(deftest string-header-names-test
  (testing "string header names work in headers map"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers {"x-custom-header" "custom-value"
                                                                    "content-security-policy" "default-src 'none'"}})]})
          headers (get-response-headers app "/")]
      (is (= "custom-value" (get headers "X-Custom-Header")))
      (is (= "default-src 'none'" (get headers "Content-Security-Policy")))))

  (testing "mixed keyword and string header names work together"
    (let [app (test-client {:routes ["/" (constantly {:status 200 :body "ok"})]
                            :extensions [(z.headers/init {:headers {:x-frame-options "DENY"
                                                                    "X-Content-Type-Options" "nosniff"}})]})
          headers (get-response-headers app "/")]
      (is (= "DENY" (get headers "X-Frame-Options")))
      (is (= "nosniff" (get headers "X-Content-Type-Options")))))

  (testing "string header names work with :remove"
    (let [handler (fn [_] {:status 200
                           :headers {"Server" "Jetty"}
                           :body "ok"})
          app (test-client {:routes ["/" handler]
                            :extensions [(z.headers/init {:headers {"server" :remove}})]})
          headers (get-response-headers app "/")]
      (is (not (contains? headers "Server"))))))
