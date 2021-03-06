; Copyright (C) 2006, Ephemeral Security, LLC
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

(module "lib/eval")
(import "lib/compile")
(import "lib/optimize")

(define (exec block)
    ((assemble (optimize (compile block)))))

(define (eval expr)
  (exec (list expr)))

(define (load-ms path)
  (exec (read-lisp-file path)))

(define (load path)
  (cond ((string-ends-with? path ".ms") (load-ms path))
        ((string-ends-with? path ".mo") (load-mo path))
        (else "lib/eval load can only handle .mo and .ms files")))

(export eval load-ms load exec)
