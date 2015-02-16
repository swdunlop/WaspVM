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

(module "lib/env")
(import "lib/iterate")

(define *in-winnt*   (string-begins-with? *platform* "win-"))
(define *in-win32*   *in-winnt*)
(define *in-darwin*  (string-begins-with? *platform* "darwin"))
; We need to test if this is GNU/Darwin, or OS X ?
(define *in-macosx*  *in-darwin*)
(define *in-posix*   (not *in-win32*))

(define *env* (make-dict))
(define tc (apply make-tc *environ*))
(until (tc-empty? tc)
  (define args (string-split (tc-next! tc) "="))
  (define key (if *in-win32* (string->uppercase (car args)) (car args)))
  (define value (cadr args))
  (dict-set! *env* key value))

(define (has-env name) (dict-ref *env* name))
(define (get-env name) (has-env name))
(define (env-is name val)
    (equal? (get-env name) val))

(define *in-x11*     (has-env "DISPLAY"))

(define (locate-cmd name)
  (apply locate-path name
         (string-split* (get-env "PATH")
                        (if *in-win32* ";" ":"))))

(define-macro (osdef formals . cases)
    (define (gen-case case)
      `(,(car case) (function ,formals ,@(cdr case))))

    `(define ,(car formals) (cond ,@(map gen-case (filter pair? cases)))))

(export osdef locate-cmd env-is get-env has-env *env*
        *in-win32* *in-x11* *in-posix* *in-darwin* *in-macosx* *in-winnt*)

