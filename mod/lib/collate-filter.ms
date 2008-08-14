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
(export prepend-collation-filter check-collation-filter)

; This filter will prepend data with a length prior to transmission.
(define-filter (prepend-collation-filter)
  (forever
    (define evt (wait in))
    (when (string? evt)
      (string-prepend! evt 
                       (quad->string (string-length evt))))
    (send evt out)))

; This filter will refuse to produce data until its full length has been
; digested.
(define-filter (check-collation-filter)
  (define buf (make-string))

  (define (wait-for-any)
    (forever
      (define evt (wait in))
      (when (string? evt)
        (string-append! buf evt)
        (return))
      (send evt out)))
  
  (define (wait-for-field len)
    (while (< (string-length buf) len)
      (wait-for-any))
    (string-read! buf len))
  
  (define (wait-for-int)
    (string->quad (wait-for-field 4)))
  
  (forever
    (define len (wait-for-int))
    (define msg (wait-for-field len))
    (send msg out)))

