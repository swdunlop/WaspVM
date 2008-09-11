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

(define *env* (map (lambda (var) (string-split var "=")) *environ*))

(define (has-env name) (assoc name *env*))

(define (get-env name)
    (define var (has-env name))
      (if var (cadr var)
                  #f))

(define (env-is name val)
    (equal? (get-env name) val))

(define *in-winnt*   (string-begins-with? *platform* "win-"))
(define *in-win32*   *in-winnt*)
(define *in-darwin*  (string-begins-with? *platform* "darwin"))
; We need to test if this is GNU/Darwin, or OS X ?
(define *in-macosx*  *in-darwin*)
(define *in-posix*   (not *in-win32*))
(define *in-x11*     (has-env "DISPLAY"))

(define (locate-cmd name)
  (apply locate-path name
         (string-split* (cadr (assoc "PATH" *env*))
                        (if *in-win32* ";" ":"))))
