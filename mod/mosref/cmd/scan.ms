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

(module "mosref/cmd/scan")
(import "mosref/shell")
(import "mosref/node")
          
(define-cmd "scan" 
            "scan <hosts> <ports> [<conns> [<timeout>]]"
            (string-append
                  "Performs a TCP port scan of the specified host, reporting"
                  " all ports that respond with a connection within timeout"
                  " milliseconds.  The scanner will limit the number of attempted"
                  " connections to conns."
                  "\n\n"
                  "When omitted, timeout defaults to 15000, and conns defaults to"
                  " 500.  Scan will only try each connection once -- to"
                  " exhaustively test unreliable or congested environments,"
                  " perform the scan multiple times to get an accurate sample.")

  (define hosts (parse-host-spec
                  (req-term terms "hosts.")))
  (define ports (parse-port-spec 
                  (req-term terms "ports.")))
  (define conns (or (opt-integer terms "conns")
                    500))
  (define timeout (or (opt-integer terms "timeout")
                      15000))
  (spawn-node-scan (mosref-shell-node shell)
                   hosts ports conns timeout))

(define *node-scan-prog*
  (inline (export nothing)
          (import "mosref/scanner")
          (define results (apply spawn-scanners (wait)))
          (forever
            (define evt (wait results))
            (send evt)
            (when (eq? evt 'done)
              (return)))))

(define (spawn-node-scan node hosts ports conns timeout)
  (with-node-program node *node-scan-prog*
    (send (list hosts ports conns timeout)
          xmit)
    
    (define done #f)

    (until done
      (define evt (wait recv))
      (cond
        ((eq? evt 'done)
         (send-line "Scan complete.")
         (send 'close xmit)
         (set! done #t))

        ((eq? evt 'close)
         (send-line "Scan interrupted.")
         (send 'close xmit)
         ; TODO: Scan was terminated abruptly.
         (set! done #t))

        ((not (list? evt))
         (send-line "Illegal scan event: " (format evt))
         (send 'close xmit)
         (send-line "Aborted scan.")
         (set! done #t))

        ((eq? (car evt) 'connect)
         (define args (cdr evt))
         (define addr (car args))
         (define port (cadr args))
         ; TODO: Scan found a port..
         (send-line "Found port: " (format-ipv4 addr) ":" (format port)))

        (else
         (send-line "Illegal scan event: " (format evt))
         (send 'close xmit)
         (send-line "Aborted scan.")
         (set! done #t))))))

