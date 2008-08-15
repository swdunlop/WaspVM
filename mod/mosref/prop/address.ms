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

(module "mosref/prop/address")

(import "mosref/node")
(import "mosref/parse")
(import "mosref/format")

(define-prop (address addr)
             doc: "Assigns an IPv4 or DNS address to the node. This address"
                  " will be used when a drone attempts to affiliate with the"
                  " node."
                  "\n\n"
                  "Drones resolve these addresses at initialization, so any"
                  " DNS addresses must be valid for resolution for the drone's"
                  " host environment."
             valid: (unless (or (string? value)
                                (integer? value))
                      (send-err "Expected DNS or IPv4 address, " 
                                (format value) "."))
                    value
             format: (format-addr value))
            
(define (node-addr node) (find-node-prop node 'address))
(define (set-node-addr! node value) (set-node-prop! node 'address value))

(export node-addr set-node-addr!)
