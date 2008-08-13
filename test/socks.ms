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

(import "lib/test")

(enable-spot-tests)

(import "lib/tcp-server")
(import "lib/socks-server")
(import "lib/socks-client")

(define localhost (resolve-addr "127.0.0.1"))
(define server-portno (random-integer 10000 30000))
(define server-listener 
  (spawn-tcp-server server-portno (lambda ()
                                    (print "SERVER: CONNECTED.\n")
                                    (send "HELO")
                                    (print "SERVER: SENT HELLO\n")
                                    (define evt (wait))
                                    (print "SERVER: GOT: ")
                                    (print (format evt))
                                    (print "\n")
                                    (send evt)
                                    (print "SERVER: SENT RESPONSE\n")
                                    (send 'close)
                                    (print "SERVER: SENT CLOSE\n"))))


(define (test-conn conn)
  (define timer (timeout 10000 (output conn) 'timeout))
  (define e (wait conn))
  (print "CLIENT: GOT ")
  (print (format e))
  (print "\n")

  (s: e)
  (r: 'connect)

  (define e (wait conn))
  (print "CLIENT: GOT ")
  (print (format e))
  (print "\n")

  (s: e)
  (r: "HELO")

  (send "Foo" conn)
  (print "CLIENT: SENT Foo.")

  (define e (wait conn))

  (print "CLIENT: GOT ")
  (print (format e))
  (print "\n")

  (s: e)
  (r: "Foo")

  (define e (wait conn))

  (print "CLIENT: GOT ")
  (print (format e))
  (print "\n")

  (s: e)
  (r: 'close)
  (cancel-timeout timer))

(define (test-proxy proxy-addr proxy-portno server-addr)
  (define conn (tcp-socks4-connect "foo"
                                   proxy-addr proxy-portno 
                                   server-addr server-portno))
  (test-conn conn))
  
(test-conn (tcp-connect "127.0.0.1" server-portno))

(define proxy-portno (random-integer 10000 30000))
(define proxy-listener (spawn-socks4-proxy proxy-portno
                                           (lambda (x)
                                             (print "Auth is: ")
                                             (print (format x))
                                             (print "\n")
                                             (string=? x "foo"))
                                           tcp-connect))

(test-proxy localhost proxy-portno localhost)
(test-proxy localhost proxy-portno "localhost")

(close-service server-listener)
(close-service proxy-listener)

