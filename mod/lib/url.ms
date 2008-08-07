; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
;
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

(module "lib/url")
(import "lib/object")

(define-class url <object>
              (make-url scheme auth path query frag)
              url?

              (scheme url-scheme)
              (auth url-auth)
              (path url-path)
              (query url-query)
              (frag url-frag))

(export <url> make-url url-scheme url-auth url-path url-query url-frag url?)

(define *url-delims* ":/?#")

(define *url-regex* 
  ;; This beast of a regex is courtesy of the W3C.  
  (make-regex "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)([?]([^#]*))?(#(.*))?"))

(define *url-parsers* (make-dict))

(define (register-url-parser key parser)
  (dict-set! *url-parsers* key parser))

(export register-url-parser *url-parsers* *url-regex*)

;; The regex produces a lot of waste results. The adapter hack ignores
;; the waste results..
(define (adapt-results-to-parser parser i1 scheme i2 auth path i3 query i4 frag)
  (parser scheme auth path query frag))

(define (string->url str)
   (define result (match-regex *url-regex* str))
   (unless result (error 'url "string is not a well formed url" str))
   (define parser (dict-ref *url-parsers* (cadr result) make-url))
   
   (apply adapt-results-to-parser parser result))

(define (string->url str (<string> scheme))
   (define result (match-regex *url-regex* str))
   (define parser (dict-ref *url-parsers* 
                            (or (cadr result) scheme)
                            make-url))
   (apply adapt-results-to-parser parser result))

(define (url->string url)
   (define buf (make-string))
   (define scheme (url-scheme url))
   (define auth (url-auth url))
   (define path (url-path url))
   (define query (url-query url))
   (define frag (url-frag url))
   
   (when scheme
     (string-append! buf (percent-encode scheme *url-delims*))
     (string-append! buf ":"))

   (when auth
     (string-append! buf "//")
     (string-append! buf (percent-encode auth *url-delims*)))

   (when path
     (string-append! buf (percent-encode path *url-delims*)))

   (when query
     (string-append! buf "?")
     (string-append! buf (percent-encode query *url-delims*)))

   (when frag
     (string-append! buf "#")
     (string-append! buf (percent-encode frag *url-delims*)))
   
   buf)

(export string->url url->string)
