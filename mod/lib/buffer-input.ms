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

(module "lib/input-channel")
(import "lib/catch")

(define (buffer-input input)
  (buffer-input input #f #f))

(define (buffer-input (#t source) (<integer> timeout))
  (buffer-input source timeout #f))

(define (buffer-input (#t source) (#t timeout) (#t debris))
  (define buffer (make-string 64))
  (set! source (input source))

  (define reject (cond 
                   (debris (set! debris (output debris))
                           (function (forward-debris event) 
                             (send event debris)))
                   (else (function (ignore-debris event)))))

  (define (process evt)
    ;(print (string-append "Processing event: " (format evt) "\n"))
    (cond ((string? evt) (string-append! buffer evt))
          ((eq? evt 'close) (reject 'close)
                            (error 'close))
          (else (reject evt))))

  (define more (cond
                 (timeout (function (more/timed)
                                 ;(print "Looking for more..\n")
                            (define event (wait timeout source))
                            (unless 
                              (eq? event 'timeout) (process event))))
                 (else (function (more/patient)
                                 ;(print "Looking for more..\n")
                          (define event (wait source))
                          (process event)))))

  (function (read-input-buffer amt)
    (when (eq? amt 'rest)
      (return (string-read! buffer (string-length buffer))))
    
    (catch-case (((close) (return 'close))
                 (else (re-error err)))
      (while (< (string-length buffer) amt)
        (more)))

    ;(print "Returning first ") (print (format amt)) (print " of ") (print (format buffer)) 
    ;(print "\n")
    ;(define result (string-read! buffer amt))
    ;(print "Which is: ") (print (format result)) (print (format (string-length result))) (print "\n")
    ;result))
    (string-read! buffer amt)))

(define (error-on-close fn)
  (function (close-monitor . args)
    (define result (apply fn args))
    (when (eq? result 'close)
      (error 'close "input closed" fn))
    result))

(define (buffer-input/eoc . rest)
  (error-on-close (apply buffer-input rest)))

(export error-on-close buffer-input buffer-input/eoc)

