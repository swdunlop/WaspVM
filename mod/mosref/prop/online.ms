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

(module "mosref/prop/online")

(import "mosref/node")
(import "mosref/parse")
(import "mosref/format")

(define-prop (online onlineno pn)
             doc: "Determines whether a node is considered to be online and"
                  " accessible by the console or other nodes.  This is normally"
                  " updated as network disconnects are detected and drones"
                  " affiliate."

             valid: (cond ((string? value) (parse-flag value))
                          ((boolean? value) value)
                          (else 
                            (send-err "Expected a flag, not " (format value)
                                      ".")))
             format: (format-flag value))

(define (node-online node) (find-node-prop node 'online))

(define (set-node-online! node value) (set-node-prop! node 'online value))

(export node-online set-node-online!)
