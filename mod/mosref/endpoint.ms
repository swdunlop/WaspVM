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

(module "mosref/endpoint")

(import "lib/object")
(import "lib/bridge")
(import "lib/with-io")

;; A MOSREF endpoint is a bridge, with a endpointing function that is invoked
;; whenever a new lane comes in.  The drone endpoint, defined elsewhere,
;; responds to incoming lanes by spawning the first function with the lane as
;; the input and output.  
;;
;; The console endpoint, defined elsewhere, currently does nothing, but will
;; eventually serve modules from a specified directory at the drone's request.

(define (spawn-endpoint endpoint xmit recv)
  ;(set! xmit (output-chain xmit (trace-filter "XMIT")))
  ;(set! recv (input-chain  recv (trace-filter "RECV")))
  (define bridge (make-bridge xmit recv))
  (define lanes (bridge-lanes bridge))

  (spawn (lambda ()
           (forever
             (define lane (wait lanes))
             (with-input (lane-recv lane)
               (with-output (lane-xmit lane)
                 (spawn endpoint))))))
  bridge)

(export spawn-endpoint)
