; Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
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

(import "lib/test")
(import "lib/http-url")
(import "lib/http-server")
(import "lib/spawn-connection")

(enable-spot-tests)

(define last-request #f)
(define response-queue (make-queue))

(define (my-responder request) 
  (set! last-request request)
  (apply write-http-response (wait response-queue)))

(define conn (spawn-connection http-service my-responder))
(send "GET /index.ms?a=1&b=2#frag HTTP/0.1\n\n" conn)
(pause)

(s: last-request)

(t: (http-request? _))
(t: (equal? (http-request-method _) "GET"))
(t: (equal? (dict->list (http-request-headers _)) '()))

(t: (set! last-url (http-request-url _))
    (http-url? last-url))

(t: (equal? (url-scheme last-url) "http"))
(t: (equal? (url-path last-url) "/index.ms"))
(t: (equal? (url-query last-url) "a=1&b=2"))
(t: (equal? (url-frag last-url) "frag"))
(t: (equal? (http-url-arg last-url "a") "1"))

(t: (equal? (http-request-version _) "HTTP/0.1"))
(t: (equal? (http-request-body _) #f))

(send `(,last-request 200 "OK" 
        ("Content-type: text/plain" ) 
        "The quick brown fox")
      response-queue)

(s: (wait 100 conn))
(t: (equal? _ 
      "HTTP/1.1 200 OK\r\nContent-type: text/plain\r\n\r\nThe quick brown fox"))

