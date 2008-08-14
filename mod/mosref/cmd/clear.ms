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

(module "mosref/cmd/clear")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "clear"
            "clear <key> ..."
            (string-append
              "Resets zero or more properties on the current node to their"
              " default value.")

  (define node (mosref-shell-node shell))
  (define count 0)
  (until (tc-empty? terms)
    (clear-node-prop! node (resolve-key (tc-next! terms)))
    (set! count (+ count 1)))
  (send-line (case count
               ((0) "No properties cleared.")
               ((1) "Property cleared.")
               (else (string-append (format count) " properties cleared.")))))

