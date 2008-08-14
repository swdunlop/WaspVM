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

(module "mosref/model")
(import "lib/clue")
(import "lib/defdb")

; See [1.1] of "The MOSREF Data Model"

(define-table host)
(define-new host)
(define-field host os)
(define-field host arch)
(define-field host name)
(define-field host domain)

; See [1.2] of "The MOSREF Data Model"

(define-table address)
(define-new address ip host)
(define-field address ip)
(define-field address host)

; See [1.3] of "The MOSREF Data Model"

(define-table service)
(define-new service address port)
(define-foc service address port)
(define-field service address)
(define-field service port)

; Invoked when a new port has been discovered by the scanner:

(define (collate-addr-port ip port)
  (define addr (find-address-by-ip ip))

  (if (null? addr)
    (new-service (new-address ip (new-host)) port)
    (foc-service (car addr) port)))

