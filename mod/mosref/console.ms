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

(module "mosref/console")

(import "mosref/base")
(import "mosref/endpoint")

(import "lib/cfb")
(import "lib/crypto-filter")
(import "lib/buffer-channel")
(import "lib/build")

(import "lib/with-io")
(import "lib/line-filter")
(import "lib/s-filter")
(import "lib/package-filter")

(export console-affiliation console-repl make-drone-exe make-console-ecdh)

(import "lib/iterate")

;(define-macro (step . rest) '(begin))
(define (step label . items)
  (print (string-append "  CONSOLE: "
                        (apply string-append label (map format items)) 
                        "..." 
                        *line-sep*)))

(define (make-console-ecdh) (make-ecdh-key *ecdh-keysize*))

(define (console-affiliation session-ecdh xmit recv)
  ;;;TODO: Configure timeout.
  (define read (buffer-channel recv))

  (define console-iv (make-iv))

  (step "Reading Drone Public Key")
  ;;; Drone --> Console, via plaintext, Dp
  (define drone-ecdh (import-ecdh (read 59)))
  (define aes-key (make-aes-key 256 
                                (ecdh-shared-secret session-ecdh drone-ecdh)))

  (step "Reading Drone IV")
  ;;; Drone --> Console, via KK, DD
  (define drone-iv (aes-decrypt aes-key (read 16)))

  (step "Transmitting Console IV")
  ;;; Console --> Drone, via KK, CC
  (send (aes-encrypt aes-key console-iv) xmit)
  
  (define report (make-mosref-recv recv aes-key drone-iv))
  (define command (make-mosref-xmit xmit aes-key console-iv))

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

(define (make-drone-exe console-addr console-portno console-ecdh platform)
  (build-exe platform
             `((import "mosref/drone")
               (import "mosref/endpoint")
               (import "lib/cons-filter") ;TODO: Should be forwarded..
               (import "lib/format-filter") ;TODO: Should be forwarded..
               (define conn (tcp-connect ,console-addr ,console-portno))
               (apply spawn-endpoint 
                      drone-endpoint
                      (drone-affiliation 
                        (import-ecdh
                          (base64-decode ,(base64-encode (export-public-ecdh 
                                                           console-ecdh))))
                        (input conn)
                        (output conn))))))

;;TODO: import handler.
(define (console-endpoint) (send 'close))

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
    (dict (cons 'quit
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

