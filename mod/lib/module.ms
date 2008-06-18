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

; Expands on core/module

(module "lib/module")

(define *core-deps* (list "core/macro"
                          "core/config" 
                          "site/config"
                          "core/file"
                          "core/module"
                          "core/io"))

(define (core-dependencies) *core-deps*)

(define (code-imports module)
  ;;; Returns a list of imported modules from a module.
  (define ignore (make-set))
  (define imports (make-tc))

  (define (is-import? expr)
    (and (pair? expr)
         (= (length expr) 2)
         (eq? (car expr) 'import)))

  (define (add-import expr)
    (define module (cadr expr))
    (unless (set-member? ignore module)
      (set-add! ignore module)
      (tc-add! imports module)))

  (for-each 
    add-import
    (filter is-import? (if (string? module)
                          (read-module-source module)
                          module)))

  (tc->list imports))

(define (code-exports module)
  ;;; Returns a list of exported symbols from a module.
  (define ignore (make-set))
  (define exports (make-tc))

  (define (is-export? expr)
    (and (pair? expr)
         (> (length expr) 1)
         (eq? (car expr) 'export)))

  (define (add-export symbol)
    (unless (set-member? ignore symbol)
      (set-add! ignore symbol)
      (tc-add! exports symbol)))

  (define (add-exports expr)
    (for-each add-export (cdr expr)))

  (for-each 
    add-exports
    (filter is-export? (if (string? module)
                          (read-module-source module)
                          module)))

  (tc->list exports))

(define (code-dependencies source)
  (define deps (apply make-tc (core-dependencies)))
  (define ignore (apply make-set (core-dependencies)))

  (define (process-code code)
    (for-each process-module
              (code-imports code)))

  (define (process-module module)
    (unless (set-member? ignore module)
      (set-add! ignore module)
      (process-code (read-module-source module))
      (tc-add! deps module)))

  (cond
    ((string? source) (process-module source))
    ((pair? source) (process-code source))
    (else (error 'args "expected module name or module code for source")))
  (tc->list deps))


(export code-imports code-exports code-dependencies core-dependencies)
