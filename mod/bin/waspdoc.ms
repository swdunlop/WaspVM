
(import "waspdoc/check-source")
(import "waspdoc/dump-source")

(define (main . args)
  (define orig args)
  (define arg #f)

  (define (usage)
    (send (string-append
            "USAGE: waspdoc check source -- Check source for new and missing.\n"
            "       waspdoc dump source <src-file> -- View source info.\n"
            "       waspdoc dump module <mod-name> -- View module info.\n")))

  (define (fail . args)
    (if arg
      (send (string-append "Did not understand " arg ".\n"))
      (send (string-append "Expected more.\n"))))

  (define (next-arg)
    (cond ((null? args) (set! arg #f))
          (else (set! arg (car args))
                (set! args (cdr args))))
    arg)

  (case (next-arg)
    (("check") (case (next-arg)
                 (("source") (apply check-source args))
                 (else (fail "check"))))
                 
    (("dump") (case (next-arg)
                (("source") (apply dump-source args))
                (("module") (apply dump-module args))
                (else (fail "dump"))))

    ((#f) (usage))))


