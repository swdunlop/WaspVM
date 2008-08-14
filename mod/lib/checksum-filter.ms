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

(module "lib/checksum-filter")
(import "lib/filter")
(export prepend-checksum-filter check-checksum-filter)

; This filter will prepend data with a checksum prior to transmission.
(define-filter (prepend-checksum-filter checksum)
  (forever
    (define evt (wait in))
    (when (string? evt)
      (string-prepend! evt (quad->string (checksum evt))))
    (send evt out)))

(define-filter (check-checksum-filter checksum)
  (define buf (make-string))

  (forever
    (define evt (wait in))
    (when (string? evt)
      (define c (string-read-quad! evt))
      (unless (= c (checksum evt))
        (set! evt  (list 'fail 'crc evt) out)))
    (send evt out)))

