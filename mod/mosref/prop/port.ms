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

(module "mosref/prop/port")

(import "mosref/node")
(import "mosref/parse")
(import "mosref/format")

(define-prop (port portno pn)
             doc: "Assigns a TCP port for incoming DCNR sessions.  Drones that"
                  " need to contact the node will attempt to contact this port."
                  "\n\n"
                  "The node will only listen to this port when it is informed"
                  " that one or more drones are expected to affiliate with the"
                  " node.  If a port has not been assigned, a random one will"
                  " be assigned, in the range 10000 to 30000, inclusive."
                  "\n\n"

             valid: (unless (or (string? value)
                                (integer? value))
                      (send-err "Expected a port number, not " 
                                (format value) "."))
                    (parse-port value))
            
(define (node-port node) 
  (define x (find-node-prop node 'port))
  (unless x
    (set! x (random-integer 10000 30000))
    (set-node-port! node x))
  x)

(define (set-node-port! node value) (set-node-prop! node 'port value))

(define (node-has-port? node) (has-node-prop? node 'port))

(export node-port set-node-port! node-has-port?)
