(module "waspdoc/waspdoc")
(import "lib/object")

;TODO: Waspdoc of Defined Macros
;TODO: Improve printing of (#t arg) args.

(define-class waspdoc-member <object> 
              (make-waspdoc-member module id formals)
              waspdoc-member?
              (module waspdoc-member-module)
              (id waspdoc-member-id)
              (formals waspdoc-member-formals))

(define (format-waspdoc-member member)
  (define id (waspdoc-member-id member))
  (define formals (waspdoc-member-formals member))
  (unless formals (return (format id)))
 
  (define items (make-tc))
  (tc-add! items "(")
  (tc-add! items (format id))

  (until (null? formals)
    (tc-add! items " ")

    (cond ((symbol? formals)
            (tc-add! items (format formals))
            (tc-add! items " ...")
            (set! formals '()))
          (else
            (tc-add! items (format (car formals)))
            (set! formals (cdr formals)))))

  (tc-add! items ")")
  (apply string-append (tc->list items)))

(define-class waspdoc-module <object>
              (make-waspdoc-module id imports exports)
              waspdoc-module?
              (id waspdoc-module-id set-waspdoc-module-id!)
              (imports waspdoc-module-imports)
              (exports waspdoc-module-exports))

(define (format-waspdoc-module module)
  (define items (make-tc))

  (define (append-line . fields)
    (for-each tc-add! (repeat items) fields)
    (tc-add! items *line-sep*))
  
  (define (append-header . fields) ;TODO: Don't append-line, merge first one onto line.
    (append-line @fields ": "))

  (define (append-entry . fields)
    (append-line "         " @fields))

  (define id (waspdoc-module-id module))
  (if id 
    (append-line "MODULE: " id *line-sep*)
    (append-line "ANONYMOUS MODULE" *line-sep*))

  (define imports (waspdoc-module-imports module))
  (unless (null? imports)
    (append-line "IMPORTS: " (car imports))
    (for-each append-entry (cdr imports))
    (append-line))

  (define exports (dict-values (waspdoc-module-exports module)))
  (unless (null? exports)
    (append-line "EXPORTS: " (format-waspdoc-member (car exports)))
    (for-each append-entry (map format-waspdoc-member (cdr exports)))
    (append-line))

  (apply string-append (tc->list items)))

(define (parse-waspdoc-module module)
  (when (string? module)
    (set! module (read-module-source module)))

  (define module-id #f)
  (define module-exports (make-set))
  (define module-members (make-tc))
  (define exported-members (make-dict))
  (define module-imports (make-tc))

  (define (parse-module-expr expr)
    (unless (pair? expr) (return))

    (case (car expr)
      ((import) (parse-module-import (cdr expr)))
      ((export) (parse-module-exports (cdr expr)))
      ((module) (parse-module-header (cdr expr)))
      ((define) (parse-module-define (cdr expr)))))

  (define (parse-module-import import)
    (unless (pair? import) (return))
    (set! import (car import))
    (unless (string? import) (return))
    (tc-add! module-imports import))

  (define (parse-module-exports exports)
    (for-each parse-module-export exports))

  (define (parse-module-export export)
    (unless (symbol? export) (return))
    (set-add! module-exports export))

  (define (parse-module-header header)
    (unless (pair? header) (return))
    (set! header (car header))
    (unless (string? header) (return))
    (set! module-id header))

  (define (parse-module-define definition)
    (unless (pair? definition) (return))
    (define term (car definition))
    (set! definition (cdr definition))
    
    (cond 
      ((symbol? term) (parse-module-define-var term definition))
      ((not (pair? term))) ;;Do nothing.
      ((symbol? (car term)) (parse-module-define-fn term)) 
      (else (parse-module-define-fn term))))
  
  (define (parse-module-define-var term defn)
    (tc-add! module-members (cons term #f)))

  (define (parse-module-define-fn term)
    (tc-add! module-members term))
  
  (define (bind-exported-members item)
    ;TODO: Handle the all exported case.
    (define id (car item))
    (unless (set-member? module-exports id) (return))
    (define formals (cdr item))

    (dict-set! exported-members id (make-waspdoc-member module id formals)))

  (for-each parse-module-expr module)

  ;TODO: Trap lack of a module-id and abort.

  (set! module (make-waspdoc-module 
                 module-id 
                 (tc->list module-imports) 
                 exported-members))
  
  (for-each bind-exported-members (tc->list module-members))

  module)

(define (waspdoc-module module)
  (print (format-waspdoc-module (parse-waspdoc-module module))))

