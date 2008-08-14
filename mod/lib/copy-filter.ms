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
;
(module "lib/copy-filter")
(import "lib/filter")
(export copy-filter)

(define-filter (copy-filter)
  (forever
    (define evt (wait in))
    (when (string? evt)
      (set! evt (copy-string evt)))
    (send evt out)))

