(module "waspdoc/dump-source")

(import "waspdoc/ms-file")
(import "waspdoc/dump")

(define (dump-source path)
  ;TODO
  ;(when (string-ends-with? path ".c")
  ;  (dump-waspdoc-source (waspdoc-scan-c path)))
  
  (unless (path-exists? path)
    (send (string-append "Cannot scan \"" path "\", cannot find file.\n"))
    (return))

  (when (string-ends-with? path ".ms")
    (dump-waspdoc-source (waspdoc-scan-ms path))
    (return))
  
  (send (string-append "Cannot dump informaton from \"" path 
                       "\", unrecognized file type.\n")))

(define (dump-module name)
  (dump-source (find-module-file (if (string-ends-with? name ".ms")
                                    name
                                    (string-append name ".ms")))))

(export dump-source dump-module)
