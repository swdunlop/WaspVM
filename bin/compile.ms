; Copyright (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
; All rights reserved.

(define (compile program)
  (define (make-top-context program)
    TODO)

  (define (compile-expression context expression)
    (if (symbol? expression) 
      (compile-load context expression))
      (if (pair? expression)   
        (compile-form context expression)
        (else 
          (compile-constant context expression)))) 

  (define (compile-load context variable)
    TODO)

  (define (compile-form context form)
    (define fn (case (car form)
                 ((if)     compile-if) 
                 ((fn)     compile-fn) 
                 ((var)    compile-var)
                 ((set)    compile-set)
                 ((quote)  compile-quote)
                 (else     compile-call)))

    (fn context form))

  (define (compile-if context form)
    (case (length form)
      ((1) (syntax-error "expected condition after keyword \"if\"" form))
      ((2) (compile-if-then context (cadr form) (cddr form)))
      ((3) (compile-if-then-else context (cadr form) (caddr form) (cdddr form)))
      (else (syntax-error "unexpected expression in if statement" form))))

  (define (compile-fn context form)
    (case (length form)
      ((1) (syntax-error "expected formal arguments list after keyword \"lambda\"" form))
      ((2) (syntax-error "expected at least one statement after formals in function" form))
      (else (compile-fn-formals context (cadr form) (cddr form))))
    TODO)

  (define (compile-var context form)
    TODO)

  (define (compile-set context form)
    TODO)

  (define (compile-quote context form)
    TODO)

  (define (compile-call context form)
    TODO)

  (define (compile-constant context constant)
    (list context (list 'ldc constant)))

  TODO)
