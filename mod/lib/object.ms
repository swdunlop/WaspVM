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

;; lib/object must be readble by scheme, but does not need to be executable --
;; @( ) forms must not be used; instead, use (scatter expr).

(module "lib/object")
(import "lib/iterate")

(define <object> (make-tag 'object #f))

(define (class-fields (<tag> class)) (cdr (tag-info class)))
(define (super-class (<tag> class)) (car (tag-info class)))
(define (make-class class-name super-class fields)
  (make-tag class-name super-class (scatter (class-fields super-class))
                                   (scatter fields)))

(define (make-class-constructor class-name class arg-names)
  (define fields (class-fields class))
  (define field-count  (length fields))
  
  (define arg-offsets  
    (map (function (set-arg-offset arg-name) 
           (or (list-index (lambda (x) 
                             (eq? x arg-name)) fields)
               (error 'class "constructor field is not a member of the class"
                      arg-name class-name)))
         arg-names))

  (lambda arg-values
    (let ((data (make-vector field-count)))
      (for-each (lambda (arg-offset arg-value) 
                  (vector-set! data arg-offset arg-value))
                arg-offsets
                arg-values)
      (cell class data))))

(define (make-field-accessor class field-name)
  (define field-offset (list-index (lambda (x) (eq? x field-name))
                                   (class-fields class)))
  (function (field-accessor inst) (vector-ref (repr inst) field-offset)))

(define (make-field-modifier class field-name)
  (define field-offset (list-index (lambda (x) (eq? x field-name))
                                   (class-fields class)))
  (function (field-modifier inst value) 
    (vector-set! (repr inst) field-offset value)))

(define (make-class-predicate class)
  (define ancestry (make-tc))
  (while class
         (tc-append! ancestry class)
         (set! class (super-class class)))
  (set! ancestry (tc->list ancestry))

  (lambda (value) (and (cell? value) (memq (tag value) ancestry))))
    
(define-macro (define-class class-tag super-class 
                            make-proto pred-name . class-fields)

  (define class-name (make-symbol "<" class-tag ">"))
  
  (define (bind-field-accessor access-name field-name)
    `(deflet ,access-name
       (make-multimethod 
         (list ,class-name) 
         (make-field-accessor ,class-name (quote ,field-name))
         (if (function? (? ,access-name))
            (? ,access-name) 
            refuse-method))))

  (define (bind-field-modifier modif-name field-name)
    `(deflet ,modif-name 
       (make-multimethod 
         (list ,class-name #t) 
         (make-field-modifier ,class-name (quote ,field-name))
         (if (function? (? ,modif-name))
            (? ,modif-name) 
            refuse-method))))

  (append
    '(begin)
    `((define ,class-name  (make-class ',class-tag 
                                       ,super-class 
                                       ',(map-car class-fields))))
    `((define (,pred-name %value) (isa? %value ,class-name)))
    `((define ,(car make-proto) (make-class-constructor 
                                  ',class-name 
                                  ,class-name
                                  ',(cdr make-proto))))
    (map (lambda (field) 
           (if (> (length field) 1)
             (bind-field-accessor (cadr field) (car field))
             '(begin)))
         class-fields)

    (map (lambda (field) 
           (if (> (length field) 2)
             (bind-field-modifier (caddr field) (car field))
             '(begin)))
         class-fields)))

(export make-class
        class-fields make-class-constructor make-field-modifier  
        define-class make-field-accessor
        <object>)

