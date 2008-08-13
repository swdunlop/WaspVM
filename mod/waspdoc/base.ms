(module "waspdoc/base.ms")

(define *waspdoc-root* ".")
(define (waspdoc-root) *waspdoc-root*)
(define (set-waspdoc-root! path)
  (set! *waspdoc-root* path))

(export set-waspdoc-root! waspdoc-root)

