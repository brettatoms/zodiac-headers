# Zodiac Headers

[![Clojars Project](https://img.shields.io/clojars/v/com.github.brettatoms/zodiac-headers.svg)](https://clojars.org/com.github.brettatoms/zodiac-headers)
[![cljdoc](https://cljdoc.org/badge/com.github.brettatoms/zodiac-headers)](https://cljdoc.org/d/com.github.brettatoms/zodiac-headers)

A [Zodiac](https://github.com/brettatoms/zodiac) extension for adding secure HTTP headers to your application.


> [!WARNING]
> If you add this extension to an existing project it will very likely break a lot of things.  In particular the default [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP) policy added by zodiac-headers could prevent Javascript from running, images from loading, etc.  For most sites you'll want to add a custom CSP policy.

## Installation

```clojure
com.github.brettatoms/zodiac-headers {:mvn/version "0.1.0"}
```

## Quick Start

```clojure
(ns myapp
  (:require [zodiac.core :as z]
            [zodiac.ext.headers :as headers]))

(def routes
  ["/" {:get (fn [_] {:status 200 :body "Hello!"})}])

;; Uses the 'web' preset by default
(z/start {:routes routes
          :extensions [(headers/init)]})
```

## Presets

Five presets are provided based on [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) recommendations:

### `web` (default)
Standard web application headers:
```clojure
(headers/init {:headers headers/web})
```
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- `Cross-Origin-Opener-Policy: same-origin`

### `secure-web`
Web headers + HSTS for HTTPS:
```clojure
(headers/init {:headers headers/secure-web})
```
Adds: `Strict-Transport-Security: max-age=63072000; includeSubDomains`

### `api`
Minimal headers for JSON APIs:
```clojure
(headers/init {:headers headers/api})
```
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

### `secure-api`
API headers + HSTS:
```clojure
(headers/init {:headers headers/secure-api})
```

### `strict`
Maximum security headers:
```clojure
(headers/init {:headers headers/strict})
```
Includes all security headers plus header removal (`Server`, `X-Powered-By`).

## Customization

Presets are just maps. Use standard Clojure functions to customize:

### Add a header
```clojure
(headers/init {:headers (assoc headers/web
                               :strict-transport-security "max-age=31536000")})
```

### Remove a header
```clojure
(headers/init {:headers (dissoc headers/web :x-frame-options)})
```

### Override a header value
```clojure
(headers/init {:headers (assoc headers/web
                               :x-frame-options "SAMEORIGIN")})
```

### Merge presets
```clojure
(headers/init {:headers (merge headers/api
                               {:content-security-policy "default-src 'none'"})})
```

### Build from scratch
```clojure
(headers/init {:headers {:x-content-type-options "nosniff"
                         :referrer-policy "no-referrer"}})
```

### Remove server headers
Use `:remove` as the value to strip headers from responses:
```clojure
(headers/init {:headers {:x-content-type-options "nosniff"
                         :server :remove
                         :x-powered-by :remove}})
```

## Security Notes

- **Content-Security-Policy**: The default `default-src 'self'` is a starting point. Most apps need customization.
- **HSTS**: Only use `secure-web` or `secure-api` if your site is fully HTTPS. HSTS can break local development.
- **X-Frame-Options**: Set to `DENY` by default. Use `SAMEORIGIN` if you need to embed your app in iframes on the same domain.

## References

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [securityheaders.com](https://securityheaders.com/) - Test your headers

## License

MIT License - see [LICENSE](LICENSE)
