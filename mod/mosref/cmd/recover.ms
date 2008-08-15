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

(module "mosref/cmd/recover")

(import "mosref/shell")
(import "mosref/node")
(import "mosref/listener")
(import "mosref/cmd/drone")

(define-cmd "recover"
            "recover <id>"
            (string-append
              "If the specified node is currently offline, and the node it"
              " affiliates to is currently online, directs the listening node"
              " to once again listen for the drone.  While this is useful for"
              " drones that have been terminated abruptly, it can greatly"
              " simplify man in the middle attacks and should be used"
              " carefully.")

  (define id (req-term terms " drone identifier"))
  (define next (find-mosref-node id))
  
  (unless (drone-node? next)
    (send-err "Drone node " (format id) " not found."))
  
  (when (node-online next)
    (send-err "Drone is still online, and cannot be recovered."))
  
  (define node (drone-node-link next))
  (unless (node-online node)
    (send-err "Intermediate node " (format (node-id node)) " is not online."))
  
  ;TODO: (define ecdh (make-console-ecdh)) Unnecessary?

  (spawn-drone-listener node next))

