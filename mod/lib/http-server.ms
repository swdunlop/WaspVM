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

; TODO: Parse http-request-body into URL args.

(module "lib/http-server")

(import "lib/http-url")
(import "lib/tcp-server")

(define-class http-request <object>
              (make-http-request method headers url version body input output
                                 cookies-cache)
              http-request?
              (method http-request-method)
              (headers http-request-headers)
              (url http-request-url)
              (version http-request-version)
              (body http-request-body)
              (input http-request-input set-http-request-input!)
              (output http-request-output)
              (cookies-cache http-request-cookies-cache
                             set-http-request-cookies-cache!))

(define (http-request-arg http-request key)
  (define args (http-url-args (http-request-url http-request)))
  (if args (dict-ref args key) #f))

(define (http-request-header http-request key)
  (dict-ref (http-request-headers http-request) key))

(define (split-morsels x)
  (apply append! (map (lambda (x) (string-split* x ";"))
                      (string-split* x ","))))

(define (http-request-cookie http-request key)
  (dict-ref (http-request-cookies http-request) key))

(define (parse-http-request-cookies http-request)
  (define cookies (make-dict))

  (define (parse-http-morsel morsel)
    (when (string-begins-with? morsel "$")
      (return)) ; Meta information is for the weak.
    (set! morsel (string-split morsel "="))
    (when (null? (cdr morsel))
      (return)) ; Didn't assign anything?
    ;TODO: Probably should url-decode..
    (dict-set! cookies (strip (car morsel))
                       (strip (cadr morsel))))
  
  (define (parse-http-cookie header)
    (for-each parse-http-morsel (split-morsels header)))

  (define cookie-headers (http-request-header http-request "Cookie"))

  (cond
    ((list? cookie-headers) (for-each parse-http-cookie cookie-headers))
    ((string? cookie-headers) (parse-http-cookie cookie-headers)))

  (set-http-request-cookies-cache! http-request cookies)
  cookies)

(define (http-request-cookies http-request)
  (define cache (http-request-cookies-cache http-request))
  (if cache cache (parse-http-request-cookies http-request)))
    
(define (http-response-cookie cookie)
  (define key (car cookie))
  (define value (cadr cookie))
  (define max-age (if (> (length cookie 2))
                    (cadr (cdr cookie))
                    3600))

  (string-append "Set-cookie: " key "=" value ";Max-Age=" 
                 (integer->string max-age)))

(define (http-response-cookies . cookies)
  (map http-response-cookie cookies))

(export <http-request> http-request? http-request-method http-request-headers
        http-request-url http-request-version http-request-body 
        http-request-input http-request-output http-request-header 
        set-http-request-input!  http-request-cookie http-request-arg)

(define *http-word* (make-regex "[^[:space:]]+"))
(define *http-header* (make-regex "^([^:]+):[[:space:]]+(.*)$"))

(define (read-http-request input)
  (define buffer (make-string))
  (define last-line #f)
  (define (next-line)
    (forever
      (set! last-line (string-read-line! buffer))
      (when last-line (return last-line))

      (define evt (wait input))
      (cond
        ((string? evt)
         (string-append! buffer evt))
        (else 
          (set! last-line buffer)
          (return evt)))))

  (define (next-block size)
    (until (>= (string-length buffer) size)
      (define evt (wait input))
      (cond
        ((string? evt)
         (string-append! buffer evt))
        ((eq? evt 'close)
         ; For certain badly behaved browsers..
         (set! size 0))
        (else
          (return evt))))

    (string-read! buffer size))

  (when (not (string? (next-line)))
    (error 'http "expected request line" 400 last-line))

  (define match (match-regex* *http-word* last-line))

  (unless (and match (= (length match) 3))
    (error 'http "request line malformed" 400 last-line))

  (define method (car match))
  (define url (cadr match))
  (define version (cadr (cdr match)))
  (define headers (make-dict))

  (define (read-headers)
    (forever 
      (cond 
        ((not (string? (next-line)))
         (error 'http "expected header line or null line" 400 last-line))
        ((empty-string? last-line)
         (return headers))
        (else
          (define match (match-regex *http-header* last-line))
          (unless match
            (error 'http "header line malformed" 400 last-line))
          (define key (car match))
          (define val (cadr match))
          (define old (dict-ref headers key))
          (if old
            (append! old val)
            (dict-set! headers key (list val)))))))

  (read-headers)

  (when (dict-set? headers "Transfer-Encoding")
    ;; Piss off. We're a simple little server, not an operating system..
    (error 'http "transfer encodings unimplemented" 501))

  (define body #f)
  (define content-length (car (or (dict-ref headers "Content-Length")
                                  '(#f))))
  (define content-type #f)

  (when content-length
    (guard (lambda (x) 
             ;; Integer or die!
             (error 'http "content length malformed" 400 last-line))
           (set! content-length (string->integer content-length)))
    (set! body (next-block content-length))
    (unless (string? body)
      (error 'http "content body malformed" 400 body))
    (set! content-type (car (or (dict-ref headers "Content-Type")
                                '(#f))))
    (when (equal? content-type "application/x-www-form-urlencoded")
      (set! url (string-append url "?" body))))

  (define url (string->url url "http"))

  ;TODO: Do we want to channel-prepend any excess in the buffer?

  (make-http-request method headers url version body #f input #f))  

(define *crlf* "\r\n")

(define (write-http-response port code reason headers body)
  (if (http-request? port)
    (set! port (http-request-input port)))
  (define buf (make-string))
  (string-append! buf "HTTP/1.1 ")
  (string-append! buf (number->string code))
  (string-append! buf " ")
  (string-append! buf reason)
  (string-append! buf *crlf*)
  (for-each (lambda (header) (string-append! buf header)
                             (string-append! buf *crlf*))
            headers)
  (string-append! buf *crlf*)
  (string-append! buf body)
  (send buf port)
  (send 'close port))

(define (http-service http-responder)
  (define in (current-input))
  (define out (current-output))
  (guard (lambda (e)
           (unless (eq? (error-key e) 'http) 
             (re-error e))
           (define info (error-info e))
           (guard traceback 
                  ;;; This is a hail mary -- there's a good chance that
                  ;;; the connection is in an inconsistent state. We'll
                  ;;; punch out some data, and bail.
                  (write-http-response out (cadr info) (car info)
                                       '("Content-Type: text/plain")
                                       (car info))))
     (define req (read-http-request in))
     (set-http-request-input! req out)
     (http-responder req)))

(define (spawn-http-server portno http-responder)
  (spawn-tcp-server portno http-service http-responder))

(export read-http-request write-http-response spawn-http-server http-service
        http-request-cookies http-response-cookie http-response-cookies)

