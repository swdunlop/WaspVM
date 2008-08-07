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

(module "lib/http-url")
(import "lib/url")

(define-class http-url <object>
              (make-http-url user host portno path args frag)
              http-url?
              
              (user http-url-user)
              (host http-url-host)
              (portno http-url-portno)
              (path http-url-path)
              (args http-url-args)
              (frag http-url-frag))

(export <http-url> make-http-url http-url? http-url-host http-url-portno
        http-url-path http-url-args http-url-frag http-url-user)

(define *http-auth-regex* (make-regex "^(([^@]+)@)?([^:]+)(:([0-9]+))?$"))
(define *http-arg-regex*  (make-regex "^([^=]+)(=(.*))?$"))

(define (parse-http-url scheme auth path query frag)
  (define user #f)
  (define host auth)
  (define portno #f)
  (define args #f)
  
  (define results (if auth (match-regex *http-auth-regex* auth)
                           #f))
  (when results
    (set! results (apply vector results))
    (set! user (vector-ref results 1))
    (when user (set! user (percent-decode user)))
    (set! host (vector-ref results 2))
    (when host (set! host (percent-decode host)))
    (set! portno (vector-ref results 4))
    (when portno (set! portno (percent-decode portno)))
    (cond 
      (portno (set! portno (string->integer portno)))
      (host (set! portno 80))))

  (when path 
    (set! path (map percent-decode 
                    (filter (lambda (x) (not (string=? "" x)))
                            (string-split* path "/")))))

  (when query
    (set! args (make-dict))
    (set! query (filter (lambda (x) (not (string=? "" x)))
                        (string-split* query "&")))
    (for-each (lambda (arg)
                (set! arg (match-regex *http-arg-regex* arg))
                (dict-set! args
                           (percent-decode (or (car arg) ""))
                           (percent-decode 
                             (string-replace (or (cadr (cdr arg)) "") 
                                             "+" " "))))
              query))
  
  (make-http-url user host portno path args frag))

(register-url-parser "http" parse-http-url)

(define (url-scheme (<http-url> url)) "http")

(define (url-auth (<http-url> url))
  (define buf (make-string))
  (define user (http-url-user url))
  (define host (http-url-host url))
  (define portno (http-url-portno url))

  (when host
    (when user
      (string-append! buf user)
      (string-append! buf "@"))

    (string-append! buf host)    
    
    (when portno
      (string-append! buf ":")
      (string-append! buf (number->string portno))))

  (if host buf #f))

(define (url-path (<http-url> url))
  (define path (http-url-path url))
  (if path
    (apply string-join "/" ""
           (http-url-path url))
    #f))

(define (url-query (<http-url> url))
  (define args (http-url-args url))
  (if args
    (apply string-join 
           "&"
           (map (lambda (p)
                  (string-append (car p) "=" (cdr p)))
                (dict->list args)))
    #f))

(define (url-frag (<http-url> url)) (http-url-frag url))

(export url-scheme url-auth url-path url-query url-frag)

(define (http-url-arg url arg)
  (define args (http-url-args url))
  (if args
    (dict-ref args arg)
    #f))

(export http-url-arg)
