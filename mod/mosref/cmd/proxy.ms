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

(module "mosref/cmd/proxy")
(import "mosref/shell")
(import "mosref/node")
(import "lib/socks-server")
(import "lib/tcp-server")

(define-cmd "proxy"
            "proxy [<portno> [<secret>]]"
            (string-append
              "Spawns a SOCKS 4a proxy on the console that will establish"
              " connections on the current node.  If the port number is"
              " omitted, it will be selected at random."
              "\n\n"
              "If a shared secret is supplied, the authentication supplied" 
              " to the socks proxy must be match the supplied secret.")

  (define portno (or (opt-integer terms " proxy port")
                     (random-integer 20000 30000)))

  (define secret (opt-term terms))

  (when (spawn-node-proxy (mosref-shell-node shell) portno secret)
    (send-line "SOCKS Proxy created, listening on port " (format portno) ".")))

(define *node-tcp-forward-prog* 
  (inline (export nothing)
          (define addr (wait))
          (define portno (wait))
          (define lapse (wait))
          (define conn (guard (function (handle-conn-failure err)
                                (send `(fail ,@(error-info err)))
                                (halt))
                         (start-tcp-connect addr portno)))
          (define evt (wait lapse conn))
          (cond 
            ((eq? evt 'timeout) (send '(fail "timed out"))
                                (send 'close))

            ((eq? evt 'connect) (send 'connect)
                                (spawn (function (lane-to-conn)
                                                 (forever
                                                   (define evt (wait))
                                                   (send evt conn))))
                                (spawn (function (conn-to-lane)
                                                 (forever
                                                   (define evt (wait conn))
                                                   (send evt)))))

            ((and (pair? evt) (eq? (car evt) 'fail)) (send evt)
                                                     (send 'close))

            (else (send "unrecognized response to connection attempt")
                  (send 'close)))))

(define (node-tcp-connect (<console-node> node) addr portno lapse)
  ;TODO: Put that lapse in, too.
  (start-tcp-connect addr portno))

(define (node-tcp-connect (<drone-node> node) addr portno lapse)
  (define conn (spawn-node-program node *node-tcp-forward-prog*))
  (set! conn (make-connection (cadr conn) (car conn)))
  (send addr conn)
  (send portno conn)
  (send lapse conn)
  conn)

(export node-tcp-connect)

(define (spawn-node-proxy node portno secret)
  ;TODO: Notify the console of each connection.
  (define log-channel (output))
  (define (log-line . bits)
    (define msg (string-append @bits *line-sep*))
    (send msg log-channel))
    ;(print msg)
    
  (define (node-proxy-connect addr portno)
    (define conn (node-tcp-connect node addr portno 10000))
    (define evt (wait conn))

    (cond ((eq? evt 'close) (log-line "FAIL: " 
                                      (format-addr addr) ":" (format portno) 
                                      " -- "
                                      "Connection terminated before it"
                                      " connected.")
                            #f) 
          ((eq? evt 'connect) (log-line "SUCC: "
                                        (format-addr addr) ":" (format portno) 
                                        " -- Connected.")
                              conn)
          (else (log-line "FAIL: " (format-addr addr) ":" (format portno) 
                          " -- Got unexpected response: " (format evt))
                #f)))

  (define (node-proxy-auth attempt)
    (unless (or (not secret)
                (string=? secret attempt))
      (log-line "AUTH: Failed authentication, expected " 
                (format secret) ", got " (format auth))
      (return #f))
    (return #t))
  
  (guard (lambda (err)
           (log-line "SOCKS: Could not start listener, " (car (error-info err)) ".")
           #f)

    (spawn-socks4-proxy portno node-proxy-auth node-proxy-connect)))

(export spawn-node-proxy)

