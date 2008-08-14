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

(module "mosref/cmd/nodes")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "nodes" 
            "nodes"
            "Lists the nodes currently known to the console."
  
  (send-line "NODES: " 
             (apply string-join "\n       " 
                    (map (function (format-node node)
                           (define addr (node-addr node))
                           (define port (and (node-has-port? node)
                                             (node-port node)))
                           (string-append 
                             (node-id node)
                             (if (node-online node) " online" " offline")
                             (if addr (string-append 
                                        " address: " (format-addr addr)) 
                                      "")
                             (if port (string-append 
                                        " port: " (format port)) 
                                      "")))
                         (list-mosref-nodes)))))
         
