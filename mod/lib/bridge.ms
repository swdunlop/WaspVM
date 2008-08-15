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

(module "lib/bridge")

(define-class bridge <object>
              (make-bridge-state xmit-tags recv-tags binds lanes xmit recv)
              bridge?
              (xmit-tags bridge-xmit-tags)
              (recv-tags bridge-recv-tags)
              (binds bridge-binds)
              (lanes bridge-lanes)
              (xmit bridge-xmit)
              (recv bridge-recv))

(define-class lane <object>
              (make-lane-state tag xmit recv lost closed)
              lane?
              (tag lane-tag)
              (xmit lane-xmit)
              (recv lane-recv)
              (lost lane-lost? set-lane-lost!)
              (closed lane-closed? set-lane-closed!))

(define *bridge-tag-size* 8)

(define-macro (later . stmts)
    `(spawn (function (later-thunk) ,@stmts)))

(define (make-bridge xmit recv)
  (define bridge (make-bridge-state (make-dict) (make-dict)
                                    (make-queue) (make-queue) 
                                    xmit recv))
  (bridge-monitor bridge)
  bridge)

(define (make-bridge-tag tags)
  (forever
    (define tag (read-prng *bridge-tag-size*))
    (unless (dict-ref tags tag)
      (return tag))))

(define (bridge-monitor bridge)
  (define binds       (bridge-binds     bridge))
  (define lanes       (bridge-lanes     bridge))
  (define xmit-tags   (bridge-xmit-tags bridge))
  (define recv-tags   (bridge-recv-tags bridge))
  (deflet b-xmit      (bridge-xmit      bridge))
  (deflet b-recv      (bridge-recv      bridge))

  (define (cmd-link id)
    (define lane (wait binds))
    (dict-set! recv-tags id lane))

  (define (recv-lane id lost)
    (define lane-xmit (make-queue))
    (define lane-recv (make-queue))
    (define recv-tag id)
    (define xmit-tag (make-bridge-tag xmit-tags))
    (define lane (make-lane-state xmit-tag lane-xmit lane-recv lost #f))
    (dict-set! recv-tags recv-tag lane)
    (dict-set! xmit-tags xmit-tag lane)
    (send (string-append 58 xmit-tag) b-xmit) 
    (lane-monitor bridge lane)
    lane)

  (define (cmd-make id)
    (send (recv-lane id #f) lanes))

  (define (cmd-make-res id)
    (recv-lane id #t))

  (define (cmd-data data)
    (define recv-tag (string-read! data *bridge-tag-size*))
    (define lane (dict-ref recv-tags recv-tag))
    (unless lane (bridge-wtf data))
    (define recv (lane-recv lane))
    (send data recv))

  (define (cmd-close data)
    (define recv-tag (string-read! data *bridge-tag-size*))
    (define lane (dict-ref recv-tags recv-tag))
    (when lane 
      (unless (lane-lost? lane)
        (dict-remove! recv-tags recv-tag))
      (define recv (lane-recv lane))
      (send 'close recv)))

  (define (bridge-wtf evt)
    (error 'bridge "unhandled message" evt))

  (define (shutdown)
    (define ignore (make-set))

    (define (shutdown-lane lane)
      (unless (set-member? ignore lane)
        (set-add! ignore lane)
        (send 'close (lane-recv lane))))

    (for-each shutdown-lane (dict-values recv-tags))
    (for-each shutdown-lane (dict-values xmit-tags))

    (send 'close lanes))

  (later 
    (forever
      (define evt (wait b-recv))
      (cond 
        ((eq? evt 'close)
         (shutdown)
         (halt))
        ((not (string? evt))  
         (shutdown)
         (bridge-wtf evt)
         (halt))
        ((empty-string? evt)  (bridge-wtf evt))
        (else
          ((case (string-read-byte! evt)
             ((58) cmd-link) ; :
             ((62) cmd-make) ; >
             ((93) cmd-make-res) ; ]
             ((33) cmd-data) ; !
             ((46) cmd-close) ; .
             (else bridge-wtf)) evt))))))

(define (find-reserved-lane bridge tag)
  (define lane (dict-ref (bridge-recv-tags bridge) tag))
  (when lane 
    (set-lane-lost! lane #f)
    (when (lane-closed? lane)
      (dict-remove! (bridge-recv-tags bridge) tag)))
  lane)

(define (lane-monitor bridge lane)
  (define b-xmit (bridge-xmit bridge))
  (define l-xmit (lane-xmit lane))
  (define xmit-tag (lane-tag lane))
  (define xmit-tags (bridge-xmit-tags bridge))
  (later
    (forever
      (define evt (wait l-xmit))
      ;TODO: Signal bogus messages 
      (cond
        ((string? evt)
         (send (string-append "!" xmit-tag evt) b-xmit))
        ((eq? evt 'close)
         (send (string-append "." xmit-tag) b-xmit)
         (dict-remove! xmit-tags xmit-tag))))))

; Directs the supplied bridge to create a new lane.

(define (make-a-lane bridge pfx)
  (define lane-xmit (make-queue))
  (define lane-recv (make-queue))
  (define xmit-tags (bridge-xmit-tags bridge))
  (define xmit-tag (make-bridge-tag xmit-tags))
  (define lane (make-lane-state xmit-tag lane-xmit lane-recv #f #f))
  (dict-set! xmit-tags xmit-tag lane)
  (send (string-append pfx xmit-tag) (bridge-xmit bridge))
  (send lane (bridge-binds bridge))
  (lane-monitor bridge lane)
  lane)

(define (make-lane bridge)
  (make-a-lane bridge ">"))

(define (make-reserved-lane bridge)
  (make-a-lane bridge "]"))

(export make-lane make-reserved-lane find-reserved-lane 
        lane-xmit lane-recv lane-tag lane? <lane>)

(export make-bridge bridge-lanes bridge? <bridge>)

; Extends Core/IO for Lanes

(define (input (<lane> lane)) (input (lane-recv lane)))
(define (output (<lane> lane)) (output (lane-xmit lane)))
(define (timeout (<integer> ms) (<lane> l))
  (timeout-input ms (input (lane-recv lane))))

(export input output)

