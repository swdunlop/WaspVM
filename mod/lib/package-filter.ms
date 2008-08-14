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

(module "lib/package-filter")
(import "lib/filter")

(export freeze-filter thaw-filter)

; Freezes each block as it arrives, and forwards.
; TODO: This has some unexpected responses to fail.. 
(define-filter (freeze-filter)
  (forever
    (define evt (wait in))
    (if (eq? evt 'close)
      (send evt out)
      (send (freeze evt) out))))

; Thaws each block as it arrives, and forwards.
(define-filter (thaw-filter)
  (forever
    (define evt (wait in))
    (if (string? evt) 
      (send (thaw evt) out)
      (send evt out))))

