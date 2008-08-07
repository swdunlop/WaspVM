(module "waspdoc/source")
(import "lib/object")

(define-class waspdoc-source <object>
              (make-waspdoc-source id name imports exports)
              waspdoc-source?
              
              (id waspdoc-source-id)
              (name waspdoc-source-name)
              (imports waspdoc-source-imports)
              (exports waspdoc-source-exports))

(export make-waspdoc-source waspdoc-source?  <waspdoc-source>
        waspdoc-source-imports waspdoc-source-id waspdoc-source-name 
        waspdoc-source-exports)

(define-class waspdoc-defn <object>
              (make-waspdoc-defn source id)
              waspdoc-defn?

              (id waspdoc-defn-id)
              (source waspdoc-defn-source))

(export make-waspdoc-defn <waspdoc-defn> waspdoc-defn?
        waspdoc-defn-id waspdoc-defn-source)

;; Shouldn't have to redefine id and source..
(define-class waspdoc-type-defn <waspdoc-defn> 
              (make-waspdoc-type-defn source id)
              waspdoc-type-defn?

              (id waspdoc-defn-id)
              (source waspdoc-defn-source))

(export make-waspdoc-type-defn <waspdoc-type-defn> waspdoc-type-defn?
        waspdoc-type-defn-id waspdoc-type-defn-source)

;; Shouldn't have to redefine id and source..
(define-class waspdoc-func-defn <waspdoc-defn>
              (make-waspdoc-func-defn source id formals)
              waspdoc-func-defn?
              
              (source waspdoc-defn-source)
              (id waspdoc-defn-id)
              (formals waspdoc-func-defn-formals)) 

(export make-waspdoc-func-defn <waspdoc-func-defn> waspdoc-func-defn?
        waspdoc-func-defn-formals)
              
(define (add-waspdoc-source-export! source defn)
  (define id (waspdoc-defn-id defn))
  (define exports (waspdoc-source-exports source))
  (define defns (dict-ref exports id '()))
  
  (dict-set! exports id (cons defn defns)))

(define (list-waspdoc-source-exports source)
  (dict->list (waspdoc-source-exports source)))

(export add-waspdoc-source-export! list-waspdoc-source-exports)

(define rx-morsel (make-regex "[A-Za-z0-9]+"))

(define (name->id name)
  (when (symbol? name)
    (set! name (symbol->string name)))

  (define id (apply string-join "-" (match-regex* rx-morsel name)))
  (when (string-ends-with? name "?")
    (string-append! id "q"))
  id)

(define (path->id path)
  (when (symbol? path)
    (set! path (symbol->string path)))

  (apply string-join "-" (match-regex* rx-morsel path)))

(export path->id name->id)

