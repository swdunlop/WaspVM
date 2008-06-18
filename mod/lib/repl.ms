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
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.

(module "lib/repl")

(import "lib/optimize")
(import "lib/compile")
(import "lib/eval")
(import "lib/trace")

(define (repl-syntax-err err)
  (send (string-append "SYNTAX: " (car (error-info err)) 
                       *line-sep* ">> ")))

(define (repl)
  (define done #f)

  (define input-buffer (make-string 80))
  (define input-exprs (make-tc))

  (define (read-exprs)
    (define data (wait))

    (when (eq? data 'close)
      (set! done #t)
      (return))

    (string-append! input-buffer data)

    (guard (function (catch-inc err)
             (unless (eq? (error-key err) 'inc)
               (re-error err))
             (send ".. ")
             (read-exprs))

      (tc-add! input-exprs (string->exprs input-buffer))
      (set! input-buffer (make-string 80))))

  (until done
    (send ">> ")
    (read-exprs)

    (until (tc-empty? input-exprs)
      (guard (lambda (x) (traceback x (current-output)))
        (define data (format (exec (tc-next! input-exprs))))
        (send (string-append ":: " data *line-sep*))))))
      
(export repl)
