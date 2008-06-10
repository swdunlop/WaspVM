(module "lib/import")
(import "lib/waspc")

(define core-import import)

(define (recompile-needed? path)
  (define path-ms (string-append path ".ms"))
  (define path-mo (string-append path ".mo"))
  
  (unless (path-exists? path-ms) (return #f))
  (when (path-exists? path-mo)
    (return (> (path-mtime path-ms) (path-mtime path-mo))))

  (return #t))
                        
(define (import path)
  (when (recompile-needed? path) (waspc path))
  (core-import path))

(export import)

