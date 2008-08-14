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

(module "mosref/cmd/on")
(import "mosref/shell")

(define-cmd "on"
            "on <node-id> [<command>]"
            (string-append
              "Instructs the console to perform subsequent commands on the"
              " specified node.  If an optional command is included, only that"
              " command will be performed on that node before returning to the"
              " current node.")

  (define node (req-node terms ""))
  (define old-node (mosref-shell-node shell))

  (set-mosref-shell-node! shell node)
                       
  (define (revert-node) (set-mosref-shell-node! shell old-node))

  (unless (tc-empty? terms)
    (guard (function (revert-node-before-err err)
                     (revert-node)
                     (re-error err))
           (do-mosref-cmd shell terms)
           (revert-node))))

