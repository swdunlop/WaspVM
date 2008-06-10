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
;  

(module "bin/wasp")

(import "lib/repl")
(import "lib/with-io")
(import "lib/import")

;TODO: Add a function to alter argv.

(define (main . args)
  (set! main #f)
  ;We only want to run this main once..
  
  (define (do-waspvm)
    (case (length args)
      ((0) (repl)
           (exit))
      (else  
        (let ((r (load (car args))))
          ; If main was reset, we should invoke it.
          (if main
            (apply main (cdr args))
            r)))))
  
  (do-waspvm))


