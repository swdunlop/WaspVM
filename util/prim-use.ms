(import "lib/module")

(define (find-module-globals module globals)
  ;(print (string-append "Scanning " module "...\n"))

  (define source (read-module-source module))
  
  (for-each (lambda (x)
              (unless (pair? x) (return))
              (unless (eq? (car x) 'ldg) (return))
              (set-add! globals (cadr x)))
            (compile source)))

(define (module-globals module)
  (define globals (set))
  (for-each find-module-globals 
            (code-dependencies module) 
            (repeat globals))
  globals)

(define (module-primitives module)
  (define (primitive-global? symbol)
    (primitive? (get-global symbol)))

  (filter primitive-global? 
          (module-globals module)))

(for-each 
  (lambda (x) (print (format x)) (print *line-sep*))
  (module-primitives "bin/wasp"))

