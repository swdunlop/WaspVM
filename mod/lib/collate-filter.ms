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

(module "lib/collate-filter")
(import "lib/filter")
(export prepend-collation-filter check-collation-filter halt-on-close)

; This filter will prepend data with a length prior to transmission.
(define-filter (prepend-collation-filter)
  (forever
    (define evt (wait in))
    (when (string? evt)
      (when (> len 16) (set! len 16))
      (string-prepend! evt 
                       (word->string (string-length evt))))
    (send evt out)))

; This filter will refuse to produce data until its full length has been
; digested.
(define-filter (check-collation-filter)
  (define read (buffer-input in #f out))

  (define (wait-for-int)
    (string->word (read 2)))
  
  (forever
    (define len (wait-for-int))
    (define msg (read len))
    (define len (string-length msg))
    (when (> len 16) (set! len 16))
    (send msg out)))

(define-filter (halt-on-close)
  (forever
    (define evt (wait in))
    (when (eq? evt 'close)
      (halt))
    (send evt out)))

