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

(module "mosref/drone")

(import "lib/cfb")
(import "lib/buffer-channel")
(import "lib/iterate")
(import "lib/crypto-filter")
(import "lib/package-filter")
(import "lib/tag-filter")
(import "lib/package-filter")
(import "lib/with-io")

(import "mosref/base")

;(define-macro (step . rest) '(begin))
(define (step label . items)
  (print (string-append "  DRONE: "
                        (apply string-append label (map format items))
                        "..."
                        *line-sep*)))

(define (drone-affiliation console-ecdh xmit recv)
  ;;;TODO: Configure timeout.
  (define read (buffer-channel recv))

  (step "Preparing keys")
  (define drone-iv (make-iv))
  (define drone-ecdh (make-ecdh-key 384)) 
  (define aes-key (make-aes-key 256 
                                (ecdh-shared-secret drone-ecdh console-ecdh)))

  (step "Sending Drone Public Key")
  ;;; Drone --> Console, via plaintext, Dp
  (send (export-public-ecdh drone-ecdh) xmit)

  (step "Sending Drone IV")
  ;;; Drone --> Console, via KK, DD
  (send (aes-encrypt aes-key drone-iv) xmit)

  (step "Reading Console IV")
  ;;; Console --> Drone, via KK, CC
  (define console-iv (aes-decrypt aes-key (read 16)))
 
  (define report (make-mosref-xmit xmit aes-key drone-iv))
  (define command (make-mosref-recv recv aes-key console-iv))

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

(define (drone-endpoint) 
  (with-input (input-chain (input)
                           (thaw-filter))
    (define command (wait))
    (with-output (output-chain (output)
                               (freeze-filter))
      (command))))

(export drone-affiliation drone-endpoint)

