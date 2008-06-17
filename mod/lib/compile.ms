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

; TODO: Currently, if a user redefines the name of a special form or macro,
;       overlaying it with an identifier, the macro will take precedence in
;       applicative forms --
;       (let ((let my-let-fn))
;         (let a 1))

(module "lib/compile")

(import "lib/module")
(import "lib/iterate")
(import "lib/record")

(export compile)

(define-record-type context
                    (make-context reality parent symbols slots rules exports)
                    context?
                    (reality context-reality)
                    (parent  context-parent)
                    (symbols context-symbols set-context-symbols!)
                    (slots context-slots set-context-slots!)
                    (rules context-rules set-context-rules!)
                    (exports context-exports set-context-exports!))
    
(define (add-context-slot! context slot)
  (set-context-slots! context (append (context-slots context) (list slot))))

(define (add-context-symbol! context symbol)
  (set-context-symbols! context (cons symbol (context-symbols context))))

(define (add-context-rule! context key function)
  (dict-set! (context-rules context) key function))

(define (find-context-rule context key)
  ;;;(display "Finding rule for ")
  ;;;(write key)
  ;;;(display " in ")
  ;;;(write context)
  ;;;(newline)

  (if context
    (let ((rule (dict-ref (context-rules context) key)))
      (if rule 
        rule
        (find-context-rule (context-parent context) key)))
    #f))

(define (add-context-binding! local symbol)
  (add-context-slot! (find-actual-context local)
                     (cons symbol local))
  (add-context-symbol! local symbol))

(define (make-slots context symbols)
  (map (lambda (symbol) 
         (cons symbol context))
       symbols))

(define (make-actual-context parent symbols)
  (let ((new-context (make-context #t parent symbols #f (make-dict) #f)))
    (set-context-slots! new-context 
                        (make-slots new-context symbols))
    new-context))

(define (make-top-context)
  (define top (make-actual-context #f '()))
  (define syn (apply make-dict (waspvm-syntax)))
  (let ((old-set-macro set-macro!))
    (set! set-macro! (lambda (key func)
                       (dict-set! syn key func)
                       (old-set-macro key func))))
  (set-context-rules! top syn)
  top)

(define (is-top-context? context)
  (not (context-parent context)))
                
(define (is-actual-context? context)
  (context-reality context))

(define (is-virtual-context? context)
  (not (context-reality context)))

(define (is-exported? symbol context)
  (if (context-exports context)
    (memq symbol (context-exports (find-top-context context)))
    #t))

(define (context-slot-count context)
  (length (context-slots context)))

(define (find-top-context context)
  (cond ((not context) #f)
        ((is-top-context? context) context)
        (else (find-top-context (context-parent context)))))

(define (find-actual-context context)
  (cond
    ((not context) #f)
    ((is-actual-context? context) context)
    (else (find-actual-context (context-parent context)))))

(define (make-virtual-context parent symbols)
  (let ((new-context (make-context #f parent symbols #f (make-dict) #f))
        (actual-context (find-actual-context parent)))
    (set-context-slots! actual-context
                        (append (context-slots actual-context)
                                (make-slots new-context symbols)))
    new-context))

(define (context-defines-symbol? context symbol)
  (if (memq symbol (context-symbols context)) 
      #t #f))

(define (context-slot-index context slot-context slot-symbol)
  (list-index (lambda (x) (and (eq? (car x)
                                    slot-symbol)
                               (eq? (cdr x)
                                    slot-context)))
              (context-slots context)))

(define (context-symbol-addr context symbol)
  (define result #f)
  (define actuals 0)
  (while context
    (cond ((context-defines-symbol? context symbol)
           (set! result 
             (list actuals
                   (context-slot-index (find-actual-context context)
                                       context
                                       symbol)))
           (set! context #f))
          ((is-actual-context? context)
           (set! context (context-parent context))
           (set! actuals (+ actuals 1)))
          (else
           (set! context (context-parent context)))))
  result)

(define (compile program)
  (let ((env (make-top-context)))
    (set! program (compile-exports env program))
    (compile-imports env program)
    (set! program (compile-lisp-block env program))
  (append (list (list 'usen 0 (context-slot-count env)))
          program
          (list (list 'retn)))))

(define (compile-lisp-block env block)
  (define tc (make-tc))
  (compile-defines env block)
  (for-each (lambda (expr)
              (tc-splice! tc (compile-lisp-expr env expr)))
            (compile-macros env block))
  (tc->list tc))

(define (compile-lisp-expr env expr)
  (cond ((or (boolean? expr) 
             (integer? expr)
             (string? expr)
             (procedure? expr)
             (null? expr))
         (list (list 'ldc expr)))
        ((symbol? expr)
         (let ((addr (context-symbol-addr env expr)))
           (if addr (list (cons 'ldb addr))
                    (list (list 'ldg expr)))))
        ((pair? expr)
           (compile-lisp-form env expr))
        (else
           (error 'compile "Cannot compile" expr))))
        
(define (compile-lisp-form env form)
  (define lead (car form))
  (define rest (cdr form))
  ;;;(display "Compiling Lisp Form: " )
  ;;;(write form)
  ;;;(newline)

  (if (eq? (car form) 'newf)
    (error "What the hell?" form))

  (if (eq? lead 'asm)
    (compile-asm-block env rest)
    (let ((rule (assq lead *waspvm-special-forms*)))
      ;;;(display "    special rule is: " )
      ;;;(write rule)
      ;;;(newline)
      (if rule
        (compile-lisp-expr env (apply (cdr rule) env rest))
        (let ((rule (find-context-rule env lead)))
          ;;;(display "    macro rule is: " )
          ;;;(write rule)
          ;;;(newline)
          (if rule
            (compile-lisp-expr env (apply rule (cdr form)))
            (compile-lisp-call env form)))))))

(define (compile-lisp-call env call)
  (define tc (make-tc))
  (tc-append! tc '(newf))
  (for-each (lambda (term) 
              (tc-splice! tc (compile-lisp-arg env term)))
            call)
  (tc-append! tc '(call))
  (tc->list tc))

(define (compile-lisp-arg env arg)
  (if (and (pair? arg) 
           (eq? (car arg)
                'scatter))
    (compile-lisp-arg* env (cadr arg))
    (compile-lisp-arg1 env arg)))

(define (compile-lisp-arg1 env arg)
  ;;;(display "Compiling Lisp Simple Arg: " )
  ;;;(write arg)
  ;;;(newline)

  (append (compile-lisp-expr env arg)
          '((arg))))

(define (compile-lisp-arg* env arg)
  ;;;(display "Compiling Lisp Complex Arg: " )
  ;;;(write arg)
  ;;;(newline)
  (append (compile-lisp-expr env (compile-lisp-arg*2 arg))
          '((scat))))

(define (compile-lisp-arg*2 arg)
  (if (and (pair? arg)
           (eq? (car arg) 'scatter))
    (list 'append (list 'scatter (compile-lisp-arg*2 (cadr arg))))
    arg))

(define (compile-asm-block env block)
  (define tc (make-tc))
  ;;;(display "Compiling Assembler Block: " )
  ;;;(write block)
  ;;;(newline)

  (for-each (lambda (expr)
              (tc-splice! tc (compile-asm-expr env expr)))
            block)
  (tc->list tc))

(define (compile-asm-expr env expr)
  ;;;(display "Compiling Assembler Expr: " )
  ;;;(write expr)
  ;;;(newline)

  (cond ((symbol? expr) 
         (list expr))
        ((not (pair? expr)) 
         (error 'compile "Cannot inline" expr))
        ((eq? (car expr) 'mos)
         (compile-lisp-block env (cdr expr)))
        (else (list expr))))

(define *waspvm-special-forms*
  (list
    (cons 'let (lambda (env defns . body)
                 (let ((n-env (make-virtual-context env (map car defns)))
                       (tc (make-tc)))
                   (for-each 
                     (lambda (x) 
                       (tc-splice! tc (compile-lisp-block env (cdr x)))
                       (tc-append! tc 
                                   (cons 'stb 
                                         (context-symbol-addr n-env (car x)))))
                     defns)
                   (tc-splice! tc (compile-lisp-block n-env body))
                   (cons 'asm (tc->list tc)))))
    (cons 'set!  (lambda (env term . body)
                   (unless (symbol? term)
                     (error 'compile "set! requires a symbol term" term))
                   (let ((addr (context-symbol-addr env term))
                         (tc (make-tc)))
                     (tc-splice! tc (compile-lisp-block env body))
                     (tc-append! tc (if addr (cons 'stb addr)
                                             (list 'stg term)))
                     (cons 'asm (tc->list tc)))))

    (cons 'deflet (lambda (env term . rest)
                    (let ((cmp-fn #f)
                          (id #f))
                      (cond
                        ((not (pair? term))
                         (set! cmp-fn compile-define-val)
                         (set! id term))
                        ((not (null? (cdr (last-pair term))))
                         (set! cmp-fn compile-define-fn)
                         (set! id (car term)))
                        ((any pair? term)
                         (set! cmp-fn compile-define-mm)
                         (set! id (car term)))
                        (else
                          (set! cmp-fn compile-define-fn)
                          (set! id (car term))))

                      (let ((result (cmp-fn env term rest)))
                        (compile-decl env id)
                        result))))

    (cons 'define (lambda (env term . rest)
                    (let ((cmp-fn #f)
                          (id #f))
                      (cond
                        ((not (pair? term))
                         (set! cmp-fn compile-define-val)
                         (set! id term))
                        ((not (null? (cdr (last-pair term))))
                         (set! cmp-fn compile-define-fn)
                         (set! id (car term)))
                        ((any pair? term)
                         (set! cmp-fn compile-define-mm)
                         (set! id (car term)))
                        (else
                          (set! cmp-fn compile-define-fn)
                          (set! id (car term))))

                      (compile-decl env id)
                      (cmp-fn env term rest))))

    (cons '?  (lambda (env key)
                (let ((addr (context-symbol-addr env key)))
                  (if addr 
                    (list 'asm (cons 'ldb addr))
                    (list 'get-global (list 'quote key))))))

    (cons 'function (lambda (env formals . body)
                      (define name (car formals))
                      (define info (parse-formals (cdr formals)))
                      
                      (let ((bind (car info))
                            (args (cadr info))
                            (in (make-actual-context env (cadr info))))
                      
                        (let ((ct (- (length args)
                                     (if (eq? bind 'usea) 1 0)))
                              (after (make-branch-symbol 'after))
                              (body (compile-lisp-block in body)))
                          (append (list 'asm 
                                        (list 'clos name after)
                                        (list bind ct 
                                              (context-slot-count in)))
                                  body
                                  (list '(retn)
                                        after))))))))

(set-macro! 'lambda (lambda (formals . body)
                      (apply list 'function 
                             (cons (make-branch-symbol 'anon-fn)
                                   formals)
                             body)))
(set-macro! 'define-record-type
                    (lambda (name make pred . fields)
                      (apply list 'define-class 
                             name '<object> 
                             make pred 
                             fields)))

(set-macro! 'export (lambda any '(begin)))

(set-macro! 'guard
            (lambda (fn . rest)
              (let ((el (make-branch-symbol 'exit)))
                `(asm (mos ,fn)
                      (gar ,el)
                      (mos ,(cons 'begin rest))
                      (rag)
                      ,el))))
(set-macro! 'case 
            (lambda (expr . branches)
               (define var (make-branch-symbol 'key))
               `(let ((,var ,expr))
                  ,(cons 'cond
                         (map (lambda (branch)
                                (if (eq? (car branch) 'else)
                                  branch
                                  (cons 
                                    (list 'memq var 
                                          (list 'quote (car branch)))
                                    (cdr branch))))
                              branches)))))

(set-macro! 'cond (lambda clauses 
                    (if (null? clauses)
                      '(begin)
                      (let ((clause (car clauses))
                            (clauses (cdr clauses)))
                        (if (eq? (car clause) 'else)
                          (cons 'begin (cdr clause))
                          (list 'if 
                                (car clause) 
                                (cons 'begin (cdr clause))
                                (cons 'cond  clauses)))))))

(set-macro! 'when 
            (lambda (test . rest)   
              (list 'if test (cons 'begin rest))))

(set-macro! 'unless 
            (lambda (test . rest) 
              (list 'if test '(begin) (cons 'begin rest))))

(set-macro! 'while (lambda (test . rest)  
                     (let ((enter (make-branch-symbol 'enter))
                           (exit  (make-branch-symbol 'exit)))
                       `(asm ,enter
                             (mos ,test) 
                             (jf ,exit) 
                             ,(cons 'mos rest)
                             (jmp ,enter)
                             ,exit))))
(set-macro! 'until 
            (lambda (test . rest)  
              (let ((enter (make-branch-symbol 'enter))
                    (exit  (make-branch-symbol 'exit)))
                `(asm ,enter
                      (mos ,test) 
                      (jt ,exit) 
                      ,(cons 'mos rest)
                      (jmp ,enter)
                      ,exit))))

(set-macro! 'forever
            (lambda rest  
              (let ((again (make-branch-symbol 'again)))
                `(asm ,again
                      ,(cons 'mos rest) 
                      (jmp ,again)))))

(set-macro! 'or (lambda (test . rest)  
                  (if (null? rest)
                    test
                    (let ((done (make-branch-symbol 'done)))
                      `(asm (mos ,test)
                            (jt ,done)
                            (mos ,(cons 'or rest))
                            ,done)))))

(set-macro! 'and (lambda (test . rest)  
                   (if (null? rest)
                     test
                     (let ((done (make-branch-symbol 'done)))
                       `(asm (mos ,test)
                             (jf ,done)
                             (mos ,(cons 'and rest))
                             ,done)))))

(set-macro! 'if (lambda (test t-expr . rest)
                  (let ((f-expr 
                          (case (length rest)
                            ((0) '(begin))
                            ((1) (car rest))
                            (else 
                              (error 
                                "if only accepts a test, and two branches."))))
                      (done-branch (make-branch-symbol 'done))
                      (false-branch (make-branch-symbol 'false)))
                    `(asm (mos ,test)
                          (jf ,false-branch)
                          (mos ,t-expr)
                          (jmp ,done-branch)
                          ,false-branch
                          (mos ,f-expr)
                          ,done-branch))))

(set-macro! 'return (lambda expr
                      `(asm ,(cons 'mos expr)
                            (retn))))

(set-macro! 'begin (lambda stmts
                     `(asm ,(cons 'mos stmts))))

(set-macro! 'quote (lambda (value)
                     `(asm (ldc ,value))))

(define (kmap fn ls)
  (cond
    ((null? ls) '())
    ((pair? ls) (cons (fn (car ls)) (kmap fn (cdr ls))))
    (else (fn ls))))

;;; TODO: This does not handle `(x . ,y)

(set-macro! 'quasiquote (lambda (form)
                         (define temps '())

                         (define (is-temp? x)
                           (and (symbol? x)
                                (symbol-starts-with? x 37)))

                         (define (add-temp sym)
                           (let ((temp (make-branch-symbol sym)))
                             (set! temps (cons (cons sym temp) temps))
                             temp))

                         (define (find-temp sym)
                           (define p (assq sym temps))
                           (if p (cdr p) #f))
                           
                         (define (parse-temp sym)
                           (or  (find-temp sym) 
                                (add-temp sym)))
                                             
                         (define (parse-imm form)
                           (car form))
                          
                         (define (parse-qq-term form)
                           (cond ((is-temp? form)      
                                    (list 'quote (parse-temp form)))
                                 ((not (pair? form))   
                                    (list 'quote form))
                                 ((eq? (car form) 'unquote)  
                                    (parse-imm (cdr form)))
                                 ;; Only needed when compile is running under
                                 ;; scheme..
                                 ((eq? (car form) 'unquote-splicing)  
                                    (parse-imm (cons 'scatter (cdr form))))
                                 (else                
                                    (parse-qq form))))
                                 
                         (define (parse-qq form)
                           (cons 'list (kmap parse-qq-term form)))
                         
                         (parse-qq form)))
                    
(set-macro! 'apply (lambda (fn . terms)
                     (define tc (make-tc))
                     (tc-append! tc fn)
                     (until (null? terms)
                            (let ((term (car terms)))
                              (set! terms (cdr terms))
                              (tc-append! tc 
                                          (if (null? terms)
                                            (list 'scatter term)
                                            term))))
                     (tc->list tc)))

(define (is-export? expr)
  (and (pair? expr)
       (not (null? expr))
       (eq? (car expr) 'export)))

(define (isnt-export? expr)
  (not (is-export? expr)))

(define (is-macro? expr)
  (and (pair? expr)
       (not (null? expr))
       (eq? (car expr) 'define-macro)))
 
(define (compile-defines env code)
  (until (null? code)
    (let ((expr (car code)))
      (set! code (cdr code))
      (if (and (pair? expr) (memq (car expr) '(define deflet)))
        (compile-decl env (if (pair? (cadr expr))
                            (car (cadr expr))
                            (cadr expr)))))))

(define (compile-exports env code)
  (define tc (make-tc))

  ;TODO: This needs to be a set.
  (for-each (lambda (x) (tc-splice! tc (cdr x)))
            (filter is-export? code))

  (unless (tc-empty? tc)
    (set-context-exports! env (tc->list tc)))

  (filter isnt-export? code))

(define (parse-signature args)
  (map (lambda (i) 
         (if (pair? i) 
           (car i)
           #t))
       args))

(define (compile-decl env sym)
  (cond ((and (is-top-context? env)
              (is-exported? sym env)) 
         #f)
        (else 
          (add-context-binding! env sym)
          #t)))

(define (compile-imports env code) 
  (define (compile-dependency path)
    (define code (read-module-source path))
    (define exports (list))
    
    (define (compile-imported-export expr)
       (for-each (lambda (item) 
                   (set! exports (cons item exports)))
                 (cdr expr)))
    
    (define (compile-imported-macro expr)
      (let ((args (cadr expr)))
        (define body (cdr (cdr expr)))
        (define name (car args))
        (set! args (cdr args))

        (when (memq name exports)
          (add-context-rule! env name (make-procedure name args body)))))

    (for-each compile-imported-export
              (filter is-export? code))

    (for-each compile-imported-macro 
              (filter is-macro? code)))

  ;; For scheme bootstraps, we try to analyze the code statically, because importing it
  ;; may be a problem.  This is an ugly hack, and has been around way, way too long..
  
  (define (compile-import/scheme expr) 
    (define id (cadr expr))
    (for-each compile-dependency (code-dependencies id)))
  
  (define (compile-import/waspvm expr)
    (import (cadr expr)))

  (define (is-import? expr) 
    (and (pair? expr)
         (= (length expr) 2)
         (eq? (car expr) 'import)
         (string? (cadr expr))))
    
  (define (isnt-import? expr)
    (not (is-import? expr)))

  (let ((compile-import (if *waspvm?* 
                          compile-import/waspvm 
                          compile-import/scheme)))

    (for-each compile-import (filter is-import? code))))

(define (compile-macros env code)
  (define (isnt-macro? expr)
    (not (is-macro? expr)))

  (define (compile-macro expr)
    (when (< (length expr) 3)
      (error 'compile
             "the define-macro form requires a form and a body"
             expr))
    (let ((formals (cadr expr))
          (body (cdr (cdr expr))))
      (unless (pair? formals)
        (error 'compile
               "the define-macro form requires a list for its form"
               expr))
      (let ((name (car formals))
            (args (cdr formals)))
        (add-context-rule! env name (make-procedure name args body))
        '(begin)
        
        (if (and (is-top-context? env)
                 (is-exported? name env))
          `(set-macro! (quote ,name) ,(apply list 'function 
                                             (cons name args) 
                                             body))
          '(begin)))))

  (map (lambda (expr)
         (if (is-macro? expr) 
           (compile-macro expr) 
           expr))
       code))

(define (parse-slots args)
  (map (lambda (i)
         (if (pair? i)
           (cadr i)
           i))
       args))

(define make-procedure
  (if *waspvm?*
    (lambda (name args body) 
      (define src (apply list 'function (cons name args) body))
      ((assemble (compile (list src)))))
    (lambda (name args body) (primitive-eval (apply list 'lambda args body)))))

(define *branch-index* 0)

(define (reset-branch-index)
  (set! *branch-index* 0))

(define (make-branch-symbol root) 
  (set! *branch-index* (+ *branch-index* 1))
  (string->symbol (string-append (symbol->string root) "-" (number->string *branch-index*))))

(define (make-symbol . items)
  (string->symbol 
    (apply string-append 
           (map (lambda (item) 
                  (cond ((string? item) item)
                        ;((char? item) (string item))
                        ((symbol? item) (symbol->string item))))
                items))))


(define symbol-starts-with?
  (if *waspvm?*
    (lambda (symbol char)
      (eq? (string-ref (symbol->string symbol) 0) char))
    (lambda (symbol char)
      (eq? (string-ref (symbol->string symbol) 0) 
           (integer->char char)))))

(define (compile-define-val env term expr)
  (apply list 'set! term expr))

(define (compile-define-fn env term body)
  (list 'set! (car term) (apply list 'function term body)))

(define (compile-define-mm env term body)
  ;; Bloody, nasty, vicious.. Poor multimethods don't get to know about
  ;; themselves.. It's an ugly hack
  (define name (car term))
  (define args (cdr term))

  (list 'set! name 
     (list 'make-multimethod 
           (cons 'list (parse-signature args))
           (apply list 'function (cons name (parse-slots args)) 
                  body)
           (list 'if 
                 (list 'function? (list '? name))
                 (list '? name)
                 'refuse-method))))

(define (parse-formals formals)
  (define op 'usen)
  (define rs (make-tc))
  (define sg (make-tc))
  (define mt #f)

  (until (null? formals)
    (cond ((symbol? formals)
           (tc-append! rs formals)
           (tc-append! sg #t)
           (set! formals '())
           (set! op 'usea))
;          ((pair? (car formals))
;           (let ((arg (car formals)))
;             (tc-append! sg (car arg))
;             (tc-append! rs (cadr arg))
;             (set! formals '())
;             (set! mt #t)))
          (else
            (tc-append! sg #t)
            (tc-append! rs (car formals))
            (set! formals (cdr formals)))))

  (list op (tc->list rs) (and mt (tc->list sg))))

(export reset-branch-index make-branch-symbol make-symbol symbol-starts-with?)
