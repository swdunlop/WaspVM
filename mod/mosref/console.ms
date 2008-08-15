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

(module "mosref/console")

(import "mosref/transport")

(import "lib/crypto-filter")
(import "lib/buffer-input")
(import "lib/build")

(import "lib/with-io")
(import "lib/line-filter")
(import "lib/s-filter")
(import "lib/package-filter")

(import "lib/bridge")

(export console-affiliation console-repl make-drone-exe)

(import "lib/iterate")

;(define-macro (step . rest) '(begin))
(define (step label . items)
  (print (string-append "  CONSOLE: "
                        (apply string-append label (map format items)) 
                        "..." 
                        *line-sep*)))

(define (console-affiliation session-private xmit recv)
  ;;;TODO: Ensure we handle 'close to read.
  (define read (buffer-input/eoc recv))

  (define console-iv (make-iv))

  (step "Reading Drone Public Key")
  ;;; Drone --> Console, via plaintext, Dp
  (define drone-public (read 32))
  (define traffic-key  (find-shared-secret session-private drone-public))

  (step "Reading Drone IV")
  ;;; Drone --> Console, via KK, DD
  (define drone-iv (decrypt traffic-key (read 8)))

  (step "Transmitting Console IV")
  ;;; Console --> Drone, via KK, CC
  (send (encrypt traffic-key console-iv) xmit)
  
  (define report (make-mosref-recv recv traffic-key drone-iv))
  (define command (make-mosref-xmit xmit traffic-key console-iv))

  (step "Waiting for Drone to confirm Console IV")
  ;;; Drone --> Console, via RK, CC
  (unless (string=? (wait report) console-iv)
    (error 'aff "the drone failed to confirm affiliation"))

  (step "Confirming Drone IV")
  ;;; Console --> Drone, via CK, DD
  (send drone-iv command)

  ;;; TODO: We should probably create a pseudo-stream type..
  (step "Affiliation complete.")
  (list command report))

(define (make-drone-exe console-addr sin console-portno console-public platform)
  (build-exe platform
             `((import "mosref/drone")
               (import "mosref/transport")
               (define conn (tcp-connect ,console-addr ,console-portno))
               (send ,(format sin) conn)
               (define endpoint 
                 (apply spawn-endpoint 
                        drone-endpoint
                        drone-broken
                        (drone-affiliation ,console-public
                                           (output conn)
                                           (input conn))))

               ;TODO: Send the next two statements when the drone affiliates..
               (define (import key)
                  (unless (imported? key)
                    (define lane (make-lane endpoint))
                    (define xmit (lane-xmit lane))
                    (define recv (lane-recv lane))
                    (send (string-append key ".mo") xmit)
                    (define data (wait recv))
                    (send 'close xmit)
                    (unless (string? data)
                      (error 'import "could not retrieve module from console"
                             key))
                    ((thaw data))))

               (export import)))) ; Be afraid, be very afraid..

(define (console-endpoint bridge) 
  (define path (wait))

  (unless (string? path)
    (send 'close)
    (return))
  (set! path (find-module-file path))
  (send (if path (read-data-file path)
                 #f)))

(define (console-broken bridge)
  ;TODO: (for-each break-alert terminals)
  (define drone (find-drone-by-bridge bridge))
  (define id (node-id drone))
  (alert "Drone " (format id) " has lost connection.")
  (set-node-online! (find-drone-by-bridge bridge) #f))

;; transmits the supplied program to be executed on the remote endpoint of
;; the supplied transport.

(define (spawn-drone-program program endpoint)
  (define lane (make-lane endpoint))
  (define xmit (output-chain (lane-xmit lane)
                             (freeze-filter)))
  (define recv (input-chain (lane-recv lane)
                            (thaw-filter)))
  (send program xmit)
  (list xmit recv))

(define *repl-program*
  (assemble 
    (optimize 
      (compile
        `((export nothing) ;; All private..
          (define err-output (output-chain (output)
                                           (cons-filter 'err)))
          (define res-output (output-chain (output)
                                           (cons-filter 'res)
                                           (format-filter)))
          (define out-output (output-chain (output)
                                           (cons-filter 'out)
                                           (format-filter)))
          (define (fwd-traceback err)
            (define s (make-string))
            (traceback err s)
            (send s err-output))
          
          (with-output out-output
          (spawn (function (drone-repl-process)
                    (forever 
                      (guard fwd-traceback (send ((wait)) 
                                           res-output)))))))))))

(define (spawn-drone-repl endpoint)
  (spawn-drone-program *repl-program* endpoint))

(define (console-repl xmit recv)
  (define endpoint (spawn-endpoint console-endpoint xmit recv))
  (define repl (spawn-drone-repl endpoint))
  (define repl-xmit (car repl))
  (define repl-recv (cadr repl))
 
  (define (display-syntax-error err)
    (send (string-append "SYNTAX: " (cadr err) *line-sep*)))

  (define (display-compile-error err)
    (traceback err (output))
    #f)

  (define (display-remote-error errmsg)
    (send errmsg)
    #f)

  (define (display-result item)
    (send (string-append ":: " item *line-sep*)))

  (define (display-output item)
    (send (string-append "-- " item *line-sep*)))

  (spawn (lambda ()
           (forever
             (define evt (wait repl-recv))
             (cond 
               ((eq? evt 'close) (return))
               ((not (pair? evt))) ;TODO: Bad, bad news..
               ((eq? (car evt) 'err) (display-remote-error (cdr evt)))
               ((eq? (car evt) 'res) (display-result (cdr evt)))
               ((eq? (car evt) 'out) (display-output (cdr evt)))))))
               ;TODO: else, also bad, bad news.

  (define (quit-repl cmd)
    (send 'close xmit))

  (define (eval-expr expr)
    (define prog (guard display-compile-error
                   (assemble (optimize (compile expr)))))
    (unless prog (return))
    (send prog repl-xmit))

  (define cmds 
    (make-dict (cons 'quit
                     quit-repl)))

  (define default-cmd eval-expr)

  (with-input (input-chain (input) 
                           (line-filter)
                           (s-filter :promptN "   "
                                     :errfn display-syntax-error))
    (forever
      (send ">> ")
      (define cmd (wait))
      (if (eq? cmd 'close)
        (return (send 'close))
        ((dict-ref cmds cmd default-cmd) cmd)))))

(define (console-endpoint bridge) 
  (define path (wait))

  (unless (string? path)
    (send 'close)
    (return))
  (set! path (find-module-file path))
  (send (if path (read-data-file path)
                 #f)))

(define (console-broken bridge)
  ;TODO: (for-each break-alert terminals)
  (define drone (find-drone-by-bridge bridge))
  (define id (node-id drone))
  (alert "Drone " (format id) " has lost connection.")
  (set-node-online! (find-drone-by-bridge bridge) #f))

;; transmits the supplied program to be executed on the remote endpoint of
;; the supplied transport.

