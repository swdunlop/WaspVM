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

; This filter will copy any strings prior to forwarding.  This is extremely
; useful when dealing with crypto filters, because they operate in a 
; destructive fashion.

(module "lib/fuzz-filter")
(import "lib/filter")

(export fuzz-filter)

; The fuzz filter randomly concatenates or divides string messages it receives
; to simulate the disruptive qualities of most TCP/IP implementations, disparate
; MTUs.  The fuzz filter is guaranteed to cost resources, cause ulcers, and
; torment filter users.

(define (wait/timeout duration channel)
  (define event (wait duration channel))
  (cond
    ((eq? event 'timeout)
     (error 'timeout "wait/timeout lost its patience" duration channel))
    (else event)))

(define (pass-up in out)
  (forever
    (define cmd (wait in))
    (if (string? cmd)
      (return cmd)
      (send cmd out))))

(define (pass-up/duration in out duration)
  (forever
    (define cmd (wait/timeout duration in))
    (if (string? cmd)
      (return cmd)
      (send cmd out))))

(define-filter (fuzz-filter)
  (define (chop-rule)
    (define str (pass-up in out))
    (define len (string-length str))
    (define cut (random-integer 0 (- len 1)))
    (send (substring str 0 cut) out)
    (send (substring str cut (- len cut)) out))

  (define (fuse-rule)
    (define first (pass-up in out))
    (guard (lambda (err)
             (if (eq? (error-key err) 'timeout)
               (send first out)
               (re-error err)))
        (define second (pass-up/duration in out 100))
        (send (string-append first second) out)))

  (define (pass-rule)
    (send (pass-up in out) out))

  (forever
    ((case (random-integer 1 3)
       ((1) chop-rule)
       ((2) fuse-rule)
       ((3) pass-rule)))))

