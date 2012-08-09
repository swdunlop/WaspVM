; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2012, Chris Double <chris.double@double.co.nz>
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

(module "mosref/cmd/fork")
(import "mosref/shell")
(import "mosref/node")
(import "lib/terminal")

(define-cmd "fork" 
            "fork [<window-name>]"
            (string-append
              "Creates a new MOSREF console shell session that may be used"
              " in parallel with the current one.\n\n")

  (define conn (spawn-terminal 
                 (if (tc-empty? terms)
                   "MOSREF"
                   (tc-next! terms))))
  (with-io (os-connection-input conn)
           (os-connection-output conn)

           (define console (mosref-shell-console shell))
           (define node (mosref-shell-node shell))
           (spawn (lambda () (run-mosref-shell console node)))))

