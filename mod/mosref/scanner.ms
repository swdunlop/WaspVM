; Copyright (C) 2006, Ephemeral Security, LLC
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

(module "mosref/scanner")
(import "lib/with-io")
(import "lib/shuffle")
(import "mosref/model")

(define (pairs a b y)
  (set! a (shuffle a))
  (define b0 b)
  (until (null? a)
    (define b (shuffle b0))
    (define b b0)
    (define aa (car a))
    (set! a (cdr a))
    (until (null? b)
      (send (list aa (car b)) y)
      (set! b (cdr b)))
    ;(pause)
    ))

(define (terminator ct msg out)
  (lambda ()
    ;(print "Count is: ")
    ;(print (format ct))
    ;(print *line-sep*)
    (cond
      ((<= ct 1) ;(print "Sending terminator message\n")
                 (send msg out)
                 (return))
      (else (set! ct (- ct 1))))))

(define-macro (repeat count . body)
  `(let ((%ctr ,count))
     (until (<= %ctr 0)
       (set! %ctr (- %ctr 1))
       ,@body)))

(define (scan/host-port host port lapse yield)
  ;(print (string-append "Scanning " (format host) ":" (format port) "...\n"))
  (define conn (guard (lambda x #f) 
                 (tcp-connect host port)))
  (unless conn (return))
  (define t (timeout lapse (output conn) 'timeout))
  (define evt (wait conn))
  (send 'close conn)
  (when (eq? evt 'timeout) (return))
  (cancel-timeout t)
  (when (eq? evt 'connect)
    (send (list 'connect host port) yield)))

; Given a list of hosts, a list of ports, a number of worker threads to spawn
; and a timeout in milliseconds to wait for any given connection attempt -- 
; spawns the required threads and yields a channel that will report each
; successful connection, and, when all possible combinations have been tried,
; a done.

(define (spawn-scanners hosts ports conns lapse)
  (define work (make-channel))
  (define yield (make-channel))
  (define terminate (terminator conns 'done yield))
   
  (pairs hosts ports work)
  (repeat conns (send 'halt work)
                (send 'halt work))

  (repeat conns
    ;(print "Pre-launch..\n")
    (spawn (function (scanner-process)
              ;(print "Launching scanner..\n")
              (forever
                ;(print "Waiting for work.")
                (define evt (wait work))
                (when (eq? evt 'halt) 
                  ;(print "Out of work.\n")
                  (terminate)
                  (return))
                (scan/host-port (car evt) (cadr evt) lapse yield)
                ))))

  yield)

(define (collate-scan-results src)
  (forever
    (define evt (wait src))
    (when (eq? evt 'done) (return))
    (when (eq? (car evt) 'connect)
      (apply collate-addr-port (cdr evt)))))

(define (scan hosts ports conns lapse)
  (collate-scan-results (spawn-scanners hosts ports conns lapse)))

(define (services-report)
  (define (services-report/service service)
    `(svc (* (port ,(format (service-port service))))))

  (define (services-report/address address)
    (define ip (address-ip address))

    (when (integer? ip)
      (set! ip (format-ipv4 ip)))
    
    `(addr (* (ip ,ip))
           ,@(map services-report/service (find-service-by-address address))))
 
  `(scan ,@(map services-report/address (find-clue table:address))))

(define (integer-range first last)
  (when (> first last)
    (define temp last)
    (define last first)
    (define first temp))

  (define tc (make-tc))

  (until (>= first last)
    (tc-append! tc first)
    (set! first (+ first 1)))

  (tc->list tc))

(define (port-range first last)
  (integer-range first last))

(define (addr-range first last)
  (integer-range first last))

(define (cidr base mask)
  (addr-range base (| base (- (<< 1 (- 32 mask)) 1))))

(define (ipv4 q1 q2 q3 q4)
  (+ (<< q1 24)
     (<< q2 16)
     (<< q3  8)
     q4))

(define (format-ipv4 i)
  (define (ub i)
    (if (< i 0) (+ i 256) i))

  (define buf (make-string 16))
  (string-append! buf (format (ub (>> i 24))))
  (string-append! buf ".")
  (set! i (& i $FFFFFF))
  (string-append! buf (format (>> i 16)))
  (string-append! buf ".")
  (set! i (& i $FFFF))
  (string-append! buf (format (>> i 8)))
  (string-append! buf ".")
  (set! i (& i $FF))
  (string-append! buf (format i))
  buf)

(export scan services-report port-range addr-range cidr ipv4 format-ipv4)
