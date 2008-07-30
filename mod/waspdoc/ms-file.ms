(module "waspdoc/ms-file")
(import "waspdoc/source")
(import "lib/compile")

;TODO: Manage macros.
;TODO: Manage globally shared values.

(define (waspdoc-scan-ms path)
  (define name #f)
  (define imports (make-set))
  (define exports (make-set))
  (define var-defns (make-tc))
  (define func-defns (make-tc))
  (define type-defns (make-tc))
  (define has-exports? #f)
  (define exported (make-dict))

  (define exprs (read-lisp-file path))
  
  ;;; PHASE 1: SCAN SYNTAX
  ;;; Find all of the top level syntax in the module related to import, export, 
  ;;; and definitions.
  
  (define (scan-module-expr items)
    ;TODO: Warn on double module declarations.
    (unless name
      (set! name (car items))))

  (define (scan-import-expr items)
    ;TODO: Warn on more than one item.
    ;TODO: Warn on non-string import.
    (apply set-add! imports items))

  (define (scan-export-expr items)
    ;TODO: Warn on any non-symbols.
    (set! has-exports? #t)
    (apply set-add! exports items))

  (define (scan-define-expr items)
    ;TODO: Warn on missing defined symbol.
    (unless (pair? items) (return)) 
    (define term (car items))

    ;TODO: Warn on non-symbolic term.
    (cond ((symbol? term) (tc-add! var-defns term))
          ((pair? term) (tc-add! func-defns term))))
 
  (define (scan-class-members type items)
    ;TODO: Add all accessors and modifiers to type defn.
    (define tc (apply make-tc items))

    (when (tc-empty? tc) (return))
    (define constructor (tc-next! tc))
    (scan-define-expr (list constructor))
    
    (when (tc-empty? tc) (return))
    (define predicate (tc-next! tc))
    (scan-define-expr (list (list predicate 'value)))

    (until (tc-empty? tc)
      (define field (tc-next! tc))
      (define len (length field))

      (when (> len 1)
        (scan-define-expr (list (list (cadr field) type)))
        
        (when (> len 2)
          (scan-define-expr (list (list (caddr field) type (car field))))))))

  (define (scan-define-class-expr items)
    ;TODO: Add predicate to type defn.
    ;TODO: Add constructor to type defn.
    
    (unless (pair? items) (return))
    (unless (symbol? (car items)) (return))

    (define term (make-symbol '< (car items) '>))
    (tc-add! type-defns term)
    (scan-class-members (car items) (cdr (cdr items))))
    
  (define (scan-define-record-expr items)
    ;TODO: Add predicate to type defn.
    ;TODO: Add constructor to type defn.
    
    (unless (pair? items) (return))
    (unless (symbol? (car items)) (return))

    (define term (make-symbol '< (car items) '>))
    (tc-add! type-defns term)
    (scan-class-members (car items) (cdr items)))

  (define (scan-ms-expr expr)
    ;TODO: Warn on toplevel non-pair.
    (unless (pair? expr)
      (return))
    
    ((case (car expr)
       ((import) scan-import-expr)
       ((export) scan-export-expr)
       ((define) scan-define-expr)
       ((define-class define-record-type) scan-define-class-expr)
       (else     
         (return)))      
     (cdr expr)))

  (for-each scan-ms-expr exprs)
 
  (unless name 
    (set! name (substring path 0 (- (string-length path) 3))))

  (define id (path->id name))

  (define source (make-waspdoc-source id name imports exported))
  
  ;;; PHASE 2: PURGE LOCAL DEFINES
  ;;; Remove any define not exported.
  
  (define (is-exported-term? term)
    (unless has-exports?
      (return #t))
    (set-member? exports term))
  
  (define (scan-func-defn func-defn)
    (define term (car func-defn))
    
    (when (is-exported-term? term)
      (add-waspdoc-source-export! source 
                                  (make-waspdoc-func-defn source 
                                                          (name->id term)
                                                          func-defn))))

  (define (scan-type-defn type-defn)
    (define term type-defn)
    (when (is-exported-term? term)
      (add-waspdoc-source-export! source
                                  (make-waspdoc-type-defn source 
                                                          (name->id term)))))

  (define (scan-var-defn var-defn)
    (define term var-defn)
    (when (is-exported-term? term)
      (add-waspdoc-source-export! source
                                  (make-waspdoc-defn source 
                                                     (name->id term)))))

  ;TODO: Do something with var defns.

  (for-each scan-func-defn (tc->list func-defns))
  (for-each scan-type-defn (tc->list type-defns))  
  (for-each scan-var-defn (tc->list var-defns))

  source)

(export waspdoc-scan-ms)

