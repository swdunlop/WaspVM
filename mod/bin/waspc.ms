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

; Given a source file, or the input port, and a target file, or the output
; port, compiles and outputs a frozen file.

(define usage

"waspc [OPTION] ... [SOURCE-FILE] ...
Compiles Wasp Lisp programs.

OPTIONS:
  -exe <dest-path>       A copy of the virtual machine will be linked to the
                         compiled source files, creating a standalone program.
  -platform <platform>   When used with the -exe flag, specifies which OS
                         and architecture to compile for. 
  -stub <stub-path>      Like -platform, but specifies the exact virtual
                         machine file to use instead of looking up a generic
                         virtual machine in the stubs directory.
")

        
(import "lib/build")

(define (main . args)
  (when (null? args)
    (print usage)
    (return #f))
  
  (define exe-target #f)
  (define platform *platform*)
  (define stub-src #f)
  (define mods (make-tc))
  
  (define (parse-fail msg)
    (print (string-append "WASPC:" msg *line-sep*)))
  
  (define (parse-args args)
    (when (null? args) (return))
  
    (define arg (car args))
    (set! args (cdr args))
  
    (cond 
      ((string=? arg "-exe")
       (when (null? args) (parse-fail "Expected file name after -exe."))
       (set! exe-target (car args))
       (set! args (cdr args)))
      ((string=? arg "-stub")
       (when (null? args) (parse-fail "Expected file name after -stub."))
       (set! stub-src (car args))
       (unless (path-exists? stub-src)
         (parse-fail "Stub file does not exist."))
       (set! args (cdr args)))
      ((string=? arg "-platform")
       (when (null? args) (parse-fail "Expected platform ID after -platform."))
       (set! platform (car args))
       (set! args (cdr args)))
      ((string-begins-with? arg "-")
       (parse-fail (string-append "Unrecognized option: " arg)))
      (else (tc-add! mods arg))) 
  
    (parse-args args))
  
  (parse-args args)

  (define old-build-module build-module)
  (set! build-module (lambda (item)
                       (print (string-append "BUILD: " item *line-sep*))
                       (old-build-module item)))
  (set! mods (tc->list mods))
  (set! mods (apply build-modules mods))
  
  (when exe-target
    ;TODO: This is pretty brute force..
    (define imports (map (lambda (item)
                           (list 'import item))
                         (filter (lambda (item)
                                   (not (string-begins-with? item "core/")))
                                 mods)))
    (write-data-file exe-target 
      (if stub-src 
        (build-exe-with-stub (read-data-file stub-src) imports)
        (build-exe platform imports)))))
  
