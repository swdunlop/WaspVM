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

(module "mosref/drone")

(import "lib/buffer-input")
(import "lib/iterate")
(import "lib/crypto-filter")
(import "lib/package-filter")
(import "lib/tag-filter")
(import "lib/package-filter")
(import "lib/with-io")

(import "mosref/transport")

;(define-macro (step . rest) '(begin))
(define (step label . items)
  (print (string-append "  DRONE: "
                        (apply string-append label (map format items))
                        "..."
                        *line-sep*)))

(define (drone-affiliation console-public xmit recv)
  ;;;TODO: Configure timeout.
  (define read (buffer-input/eoc recv))

  (step "Preparing keys")
  (define drone-iv (make-iv))
  (define drone-private (make-private-key)) 
  (define drone-public  (find-public-key drone-private)) 
  (define traffic-key (find-shared-secret drone-private console-public))

  (step "Sending Drone Public Key")
  ;;; Drone --> Console, via plaintext, Dp
  (send drone-public xmit)

  (step "Sending Drone IV")
  ;;; Drone --> Console, via KK, DD
  (send (encrypt traffic-key drone-iv) xmit)

  (step "Reading Console IV")
  ;;; Console --> Drone, via KK, CC
  (define console-iv-ct (read 8))
  (step "CONSOLE IV CT is " console-iv-ct)
  (define console-iv (decrypt traffic-key console-iv-ct))
  (step "CONSOLE IV PT is " console-iv)

  ;(define console-iv (decrypt traffic-key (read 8)))
 
  (define report (make-mosref-xmit xmit traffic-key drone-iv))
  (define command (make-mosref-recv #f recv traffic-key console-iv))

  (step "Confirming Console IV")
  ;;; Drone --> Console, via RK, CC
  (send console-iv report)

  (step "Waiting for Console to confirm Drone IV")
  ;;; Console --> Drone, via CK, DD
  (unless (string=? (wait command) drone-iv)
    (error 'aff "the console failed to confirm affiliation"))

  (step "Affiliation complete.")
  (list report command))

(define (format-fallback item)
  (list fmt (car item) (format (cdr item))))

(define *drone-bridge* #f)

(define (drone-endpoint bridge) 
  ;TODO: This should probably be an error.
  (unless *drone-bridge*
    (set! *drone-bridge* bridge))

  (with-input (input-chain (input)
                           (thaw-filter))
                           ;(trace-filter "RECV")
    (define command (wait))
    (with-output (output-chain (output)
                               (freeze-filter))
                               ;(trace-filter "SEND")
      (command))))

(define (drone-broken bridge)
  (exit 0))

(export *drone-bridge* drone-affiliation drone-endpoint drone-broken)

