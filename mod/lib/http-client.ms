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

(module "lib/http-client")

(import "lib/object")
(import "lib/url")
(import "lib/http-url")

(define (send-http-get channel url)
  (unless (string? url)
    (set! url (url->string url)))
  (define req (string-append "GET " url " HTTP/1.0\r\n\r\n"))
  (send req channel))

(define (send-http-post channel url mime body)
  (when (url? url)
    (set! url (url->string url)))
  (define req (string-append "POST " url " HTTP/1.0\r\n" 
                             "Content-Length: " 
                             (number->string (string-length body)) "\r\n"
                             "Content-Type: " mime "\r\n\r\n"
                             body))
  (send req channel))

(define *http-header* (make-regex "^([^:]+):[[:space:]]+(.*)$"))
(define *http-result* 
  (make-regex "([Hh][Tt][Tt][Pp]/[0-9.]+)[[:space:]]+([0-9]+)[[:space:]]+(.*)$"))
(define *http-size-limit* (* 16 1024 1024))

(define (read-http-response channel)
  (define buffer (make-string))
  (define last-line #f)
  (define (next-line)
    (forever
      (set! last-line (string-read-line! buffer))
      (when last-line (return last-line))
      (define evt (wait channel))
      (cond
        ((string? evt)
         (string-append! buffer evt))
        (else 
          (set! last-line evt)
          (return evt)))))

  (define (next-block size)
    (unless size (set! size *http-size-limit*))
    (until (>= (string-length buffer) size)
      (define evt (wait channel))
      (cond
        ((string? evt)
         (string-append! buffer evt))
        ((eq? evt 'close)
         (return (string-read! buffer (string-length buffer))))
        (else
          (return evt))))
    (string-read! buffer size))

  (when (not (string? (next-line)))
    (error 'http "expected response line" last-line))

  (define match (match-regex *http-result* last-line))
  (unless match
    (error 'http "could not parse server response" last-line))

  (define version (car match))
  (define code (cadr match))

  (guard (function (bad-code err)
            (error 'http "could not parse response code" last-line code))
    (set! code (string->integer code)))

  (define message (cadr (cdr match)))

  (define headers (make-dict))

  (define (read-headers)
    (forever 
      (cond 
        ((not (string? (next-line)))
         (error 'http "expected header line or null line" last-line))
        ((empty-string? last-line)
         (return headers))
        (else
          (define match (match-regex *http-header* last-line))
          (unless match
            (error 'http "header line malformed" last-line))
          (dict-set! headers (car match) (cadr match))))))

  (read-headers)

  (define body #f)
  (define content-length (dict-ref headers "Content-Length"))
  (define content-type #f)

  (when content-length
    (guard (lambda (x) 
             ;; Integer or die!
             (error 'http "content length malformed" content-length))
           (set! content-length (string->integer content-length))))

  (set! body (next-block content-length))

  (unless (string? body)
    (error 'http "content body malformed" body))

  (set! content-type (dict-ref headers "Content-Type"))

  (when (equal? content-type "application/x-www-form-urlencoded")
    (set! url (string-append url "?" body)))

  (make-http-response code message headers body #f channel))

(define-class http-response <object>
              (make-http-response code message headers body input output)
              http-response?
              (code http-response-code)
              (message http-response-message)
              (headers http-response-headers)
              (body http-response-body)
              (input http-response-input)
              (output http-response-output))
              
(export make-http-response http-response?  http-response-code http-response-message 
        http-response-body http-response-input http-response-output)

(define (with-http-url func url . rest)
  (define s-url #f)

  (cond 
    ((string? url)
     (set! s-url url)
     (set! url (string->url url)))
    (else
      (set! s-url (url->string url))))

  (unless (http-url? url)
    (error 'http "malformed url; expected HTTP URL"))

  (define stream (tcp-connect (http-url-host url) (or (http-url-portno url)
                                                      80)))
  ;TODO: tcp-connect doesn't post connect..
  ; (define evt (wait stream))
  ; (unless (eq? evt 'connect)
  ;  (send 'close stream)
  ;  (error 'http "could not connect to host" evt))
  (guard (function (close-before-fail err)
            (send 'close stream)
            (re-error err))
     (apply func stream s-url rest)
     (define result (read-http-response stream))
     (send 'close stream)
     result))

(define (http-get url)
  (with-http-url send-http-get url))

(define (http-post url mime body)
  (with-http-url send-http-post url mime body))

(export send-http-get send-http-post read-http-response http-get http-post)

