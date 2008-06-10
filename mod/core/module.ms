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

(define *waspvm?* #t)
(export *waspvm?*)

(define (can-read-file? path)
  (guard (lambda x #f)
    (define file (open-file path "r"))
    (read-file file 1)
    (close-file file)
    #t))

(define (find-module-file filename)
  (define module-dirs (apply make-tc (or (site-config 'mod-path) '())))
  (define module-found #f)
  (until (or (tc-empty? module-dirs) module-found)
    (define module-dir (tc-next! module-dirs))
    (define module-path (path-join module-dir filename))
    (when (can-read-file? module-path)
      (set! module-found module-path)))
  module-found)

(define (read-module-source path)
  (set! path (convert-path path))

  (define ms-path (find-module-file (string-append path ".ms")))
  (when ms-path
    (return (read-lisp-file ms-path)))

  (define so-path (find-module-file (string-append path *plugin-ext*)))
  (when so-path
    (return '()))
  
  (error 'module "module source cannot be found" path))

(export find-module-file read-module-source)

(define (load-mo path)
  ((thaw (read-data-file path))))

(define (load path)
  (cond ((string-ends-with? path ".mo") (load-mo path))
        (else (error 'load "core/module load can only handle .mo files"))))

;;; Subsequent load implementations can handle .ms TODO

(export load-mo load)

(define *imports* (dict))

(define (imported? key)
  (dict-set? *imports* key))

(define (import key)
  (when (imported? key)
    (return))
  
  (define path (convert-path key))

  (define mo-path (find-module-file (string-append path ".mo")))
  (when mo-path
    (load-mo mo-path)
    (return))

  (define so-path (find-module-file (string-append path *plugin-ext*)))
  (when so-path
    (define so-init 
      (string-append "wasp_init_" 
                     (string-replace (last-item (string-split* key "/"))
                                     "-" "_")
                     "_subsystem"))

    (load-subsystem so-path so-init)
    (dict-set! *imports* key #t)

    (return))
    
  (error 'import "Could not find the requested module or subsystem." key))

(define (module key)
  (dict-set! *imports* key #t))

(export imported? import module)
