(import "waspdoc/source")
(import "waspdoc/dump")
(import "waspdoc/ms-file")

(define *wasp-src-dirs* '("waspdoc"))

(define (find-source-files)
  ;TODO: Improve.
  (list "waspdoc/dump.ms"
        "waspdoc/dump-source.ms"
        "waspdoc/ms-file.ms"
        "waspdoc/check-source.ms"
        "waspdoc/source.ms"))

(define (create-func-doc-file doc-id defn)
  (write-data-file 
    doc-id 
    (string-append 
      ";;; FUNC: " (format-defn defn) "\n"
      ";;; FROM: " (waspdoc-source-name (waspdoc-defn-source defn)) "\n")))

(define (create-type-doc-file doc-id defn)
  ;TODO: MORE!
  (write-data-file 
    doc-id 
    (string-append 
      ";;; TYPE: <" (format-defn defn) ">\n"
      ";;; FROM: " (waspdoc-source-name (waspdoc-defn-source defn)) "\n")))

(define (create-defn-doc-file doc-id defn)
  (when (waspdoc-type-defn? defn) 
    (return (create-type-doc-file doc-id defn)))

  (when (waspdoc-func-defn? defn) 
    (return (create-func-doc-file doc-id defn)))

  (write-data-file
    doc-id
    (string-append
      ";;; OTHER: " (format-defn defn) "\n"
      ";;; FROM: " (waspdoc-source-name (waspdoc-defn-source defn)) "\n")))

(define (create-source-doc-file doc-id source)
  ;TODO: List all exports.
  ;TODO: List all imports. 
  (write-data-file
    doc-id (string-append 
             ";;; MODULE: " (waspdoc-source-name source) "\n"
             "\n"
             "Undocumented.\n"
             "\n")))

(define (defn-doc-id defn)
  (define source (waspdoc-defn-source defn))
  ;TODO: Depends on define type.
  (string-append (cond ((waspdoc-type-defn? defn) "type_")
                       ((waspdoc-func-defn? defn) "func_")
                       ((waspdoc-defn? defn) "defn_")
                       (else ""))
                 (waspdoc-source-id source)
                 "_"
                 (waspdoc-defn-id defn)))

(define (source-doc-id source)
  (string-append "src_"
                 (waspdoc-source-id source)))

(define (ensure-defn-doc-file defn)
  ;TODO: Register the doc id as permitted.
  
  (define doc-id (defn-doc-id defn))
  
  (unless (path-exists? doc-id)
    (define old (path-join "old" doc-id))
    (if (path-exists? old)
      (rename-file old doc-id)
      (create-defn-doc-file doc-id defn))))

(define (ensure-source-doc-file source)
  ;TODO: Register the doc id as permitted.
  
  (define doc-id (source-doc-id source))
  
  (unless (path-exists? doc-id)
    (define old (path-join "old" doc-id))
    (if (path-exists? old)
      (rename-file old doc-id)
      (create-source-doc-file doc-id source))))

(define (check-source-export defn)
  ;TODO: Register the definition for the index by global name.
  (ensure-defn-doc-file defn))

(define (check-source-exports defns)
  (for-each ensure-defn-doc-file defns))

(define (check-source-file path)
  ;TODO: Register the source for the index by module.
  (define source (waspdoc-scan-ms path))

  (ensure-source-doc-file source)

  (for-each check-source-exports (map cdr (waspdoc-source-exports source))))

(define (check-source)
  (for-each check-source-file (find-source-files)))

