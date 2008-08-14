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

(module "mosref/cmd/load")
(import "mosref/shell")
(import "mosref/cmd/do")

(define-cmd "load"
            "load <path>"
            (string-append
              "Loads the Mosquito Lisp source file, compiles it, then transmits"
              " the resulting program to the current node for execution.")
  
  (define file-name (req-term terms "lisp file name"))

  (guard (lambda (err)
           (send-err "Could not read lisp file " (format file-name) ", "
                     (cadr (error-info err))))
    (define expr (read-lisp-file file-name)))

  (eval-node-expr (mosref-shell-node shell) expr))

