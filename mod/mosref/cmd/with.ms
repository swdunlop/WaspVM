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

(module "mosref/cmd/set")
(import "mosref/shell")
(import "mosref/node")
(import "mosref/props")

(define-cmd "with"
            "with <key>[=<value>] [<command>]"
            "Performs the supplied command with key temporarily set to value."

  (define node (mosref-shell-node shell))

  (define key-val (parse-property (req-term terms)))
  (define key (car key-val))
      
  (define command terms)

  (define was-set (has-node-prop? node key))
  (define old-val (if was-set (find-node-prop node key)))

  (set-node-prop! node @key-val)
  (do-mosref-cmd shell command)
  (if was-set (set-node-prop! node key old-val)
              (clear-node-prop! node key)))

