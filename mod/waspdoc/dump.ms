(module "waspdoc/dump")

(define (send-line . items)
  (send (string-append @items "\n")))

(define (normalize-formal-arg arg)
  (unless (pair? arg) (return arg))
  (unless (= (length arg) 2) (return arg))
  (unless (eq? (car arg) #t) (return arg))
  (cadr arg))

(define (format-formals formals)
  (define buf (make-string 32))
  (string-append! buf "(" (format (car formals)))
  (set! formals (cdr formals))
  
  (forever
    (when (null? formals)
      (string-append! buf ")")
      (return buf))

    (string-append! buf " ")

    (unless (list? formals)
      (string-append! buf (format formals))
      (string-append! buf " ...)")  
      (return buf))
    
    (string-append! buf (format (normalize-formal-arg (car formals))))
    
    (set! formals (cdr formals))))

(define (format-defn (<waspdoc-defn> defn))
  (waspdoc-defn-id defn))

;; Shouldn't be necessary, but it is..
(define (format-defn (<waspdoc-type-defn> defn))
  (string-append "<" (waspdoc-defn-id defn) ">"))

(export format-defn)

(define (format-defn (<waspdoc-func-defn> defn))
  (format-formals (waspdoc-func-defn-formals defn)))

(define (dump-waspdoc-source src)
  (send-line "MODULE:  " (waspdoc-source-name src))
  (send-line "IMPORTS: " (apply string-join ", " 
                                (set->list (waspdoc-source-imports src))))
  (send-line "EXPORTS: " (apply string-join "\n         " 
                                (map format-defn 
                                  (map cadr 
                                    (list-waspdoc-source-exports src))))))

(export dump-waspdoc-source)

