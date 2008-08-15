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

(module "mosref/cmd/sh")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "sh" 
            "sh <cmd>"
            (string-append
              "Evaluates the supplied host command on the current node --"
              " this will only work on non-Windows nodes, due to"
              " limitations in the Win32 command shell.")

  (spawn-node-shell (mosref-shell-node shell) (tc->list terms)))

(define *node-shell-prog*
  (inline (export nothing)
          (import "lib/env")
          (import "mosref/patch")
          (when (string-begins-with? *platform* "win")
            (send (list 'error 
                        "MOSREF cannot spawn shell commands on Microsoft Windows"))
            (send 'close)
            (halt))

          (define cmd (wait))
          (define prog (car cmd))
          (define args (cdr cmd))

          (set! prog (locate-cmd prog))
          (unless prog
            (send (list 'error
                        (string-append "Drone cannot find " (format (car cmd) ) 
                                       ".")))
            (send 'close)
            (return))

          (define stream (spawn-command prog args))
          (define lane (make-reserved-lane *drone-bridge*))
          (send (list 'connect (lane-tag lane)))
          (patch2 stream lane)
          (send 'close)))

(define (spawn-node-shell (<drone-node> node) cmd)
  (define conn (spawn-node-program node *node-shell-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))
  (define bridge (drone-node-bridge node))
  (send cmd xmit)
  (define event (wait recv))
  (send 'close xmit)
  (when (eq? event 'close)
    (send 'close xmit)
    (send-err "Lost connection with shell process."))
  (unless (pair? event)
    (send 'close xmit)
    (send-err "Unusual message received: " (format event)))
  (when (eq? (car event) 'connect)
    (define tag (cadr event))
    (define lane (find-reserved-lane bridge tag))
    (when lane
      (define lx (lane-xmit lane))
      (define lr (lane-recv lane))
      (define tx (output))
      (define tr (input))
      (spawn (lambda ()
               (forever
                 (define e (wait lr))
                 (when (eq? e 'done)
                   (return))
                 (when (eq? e 'close)
                   (send 'done tx)
                   (return))
                 (send e tx))))
      (forever
        (define e (wait tr))
        (when (eq? e 'done)
          (return))
        (send e lx)
        (when (eq? e 'close)
          (send 'done lx)
          (send e (output tx)))))
    (send-err "Could not resolve initial lane.")
    (return))
  (when (eq? (car event) 'error)
    (send 'close xmit)
    (send-err (cadr event))))

(define (spawn-node-shell (<console-node> node) cmd)
  (when (string-begins-with? *platform* "win")
    (send-err "MOSREF cannot spawn shell commands on Microsoft Windows"))
 
  (define prog (car cmd))
  (define args (cdr cmd))
  (set! prog (locate-cmd prog))
  (unless prog
    (send-err  "Cannot find command " (format (car cmd)) "."))

  (define stream (spawn-command prog args))

  (define tx (output))
  (define tr (input))
  (define sr (input stream))
  (define sx (output stream))
  (define cmd-done #f)

  (spawn (function (relay-command-output)
           (until cmd-done
             (define e (wait sr))
             (when (eq? e 'done)
               (return))
             (when (eq? e 'close)
               (set! cmd-done #t)
               ;(send 'done tx);XX
               (return))
             (send e tx))))
    
  (define (poll-console-input)
    (define event (wait 10 tr))
    (when (eq? event 'timeout) (return))
    (send event sx))

  (until cmd-done (poll-console-input)))
