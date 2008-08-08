(module "waspdoc/c-file")
(import "waspdoc/source")

(define (waspdoc-scan-c path)
  (define name (substring path 0 (- (string-length path) 2)))
  (define id (path->id name)) ;;TODO: Where do we get path->id ?

  (define func-defns (make-tc)) 
  (define type-defns (make-tc))
  (define exported (make-dict))

  (define source (make-waspdoc-source id name (set) exported))

  (define lines (split-lines (read-data-file path)))
  
  (define (scan-c-line line)
    TODO)

  (for-each scan-c-line lines)

  source)

(export waspdoc-scan-c)
