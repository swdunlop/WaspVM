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

; field 1: socks version number, 1 byte, must be 0x04 for this version
; field 2: command code, 1 byte:-
;   0x01 = establish a tcp/ip stream connection
;   0x02 = establish a udp datagram port binding
; field 3: network byte order port number, 2 bytes
; field 4: network byte order ip address, 4 bytes
; field 5: the user id string, variable length, terminated with a null (0x00)
; field 6: dns address string if first three bytes of field 3 are null, 
;          terminated with a null (0x00).

(module "lib/socks-client")

(define (read-to-zero! str what)
  (define res (make-string (string-length str)))
  (until (empty-string? str)
    (define ch (string-read-byte! str))
    (if (= ch 0) (return res)
                 (string-append! res ch)))
  (error 'socks (string-append what " incomplete") res))

(define (format-socks4-request auth proto addr portno)
  (define str (make-string))
  (string-append-byte! str $04)
  (string-append-byte! str (case proto 
                             ((tcp) $01)
                             ((udp) $02)
                             (else (error 'socks 
                                          "expected tcp or udp protocol"
                                          proto))))
  (string-append-word! str portno)
  (string-append-quad! str (if (string? addr) $00000001
                                              addr))
  (string-append! str auth)
  (string-append-byte! str 0)

  (when (string? addr)
    (string-append! str addr)
    (string-append-byte! str 0))

  str)

; field 1: null byte
; field 2: status, 1 byte:-
;   0x5a = request granted, 
;   0x5b = request rejected or failed,
;   0x5c = request failed because client is not running identd (or not 
;          reachable from the server)
;   0x5d = request failed because client's identd could not confirm the user 
;          id string in the request
; field 3: network byte order port number, 2 bytes
; field 4: network byte order ip address, 4 bytes

(define (parse-socks4-response str)
  (unless (= (string-read-byte! str) 0)
    (error 'socks "expected null to start response"))

  (define status (string-read-byte! str))
  (define portno (string-read-word! str))
  (define addr (string-read-quad! str))

  (unless (= status $5A)
    (when (= (& addr $FFFFFF00) 0)
      (error 'socks "proxy could not resolve address" str))
    (case status
      (($5B) (error 'socks "request rejected or failed" str))
      (($5C) (error 'socks "request rejected, client unverifiable" str))
      (($5D) (error 'socks "request rejected, user unverified" str))
      (else (error 'socks "unrecognized status code" status))))

  (list status portno addr))

(export parse-socks4-response format-socks4-request)

(define (tcp-socks4-connect auth socks-addr socks-portno dest-addr dest-portno)
  (define c (tcp-connect socks-addr socks-portno))
  (define t (timeout 10000 (output c) 'timeout))
  (define e #f)

  (define (next what)
    (set! e (wait c))
    (when (eq? e 'timeout)
      (error 'timeout (string-append "timeout waiting for " what)))
    e)

  (guard (lambda (e)
           (cancel-timeout t)
           (re-error e))
    (unless (eq? (next "connect") 'connect)
      (error 'socks "could not connect to proxy" e))

    (send (format-socks4-request auth 'tcp dest-addr dest-portno) c)

    (unless (string? (next "socks response"))
      (error 'socks "lost connection to proxy" e))

    (define r (parse-socks4-response e)))

  ; Note, this is full synchronous.  We should make it asynchronous.
  (cancel-timeout t)
  (send 'connect (output c))

  ; Any data past the end, here, is data..
  (unless (empty-string? e)
    (send e (output c)))

  c)

(export tcp-socks4-connect)

