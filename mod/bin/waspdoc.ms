
(import "waspdoc/check-source")
(import "waspdoc/dump-source")

(define (main . args)
  (define opts (apply make-tc args))
  (define args (make-tc))

  (define arg #f)

  (define (exit code)
    (error 'exit code))

  (define (next-arg)
    (if (tc-empty? args) #f (tc-next! args)))

  (define (usage)
    (print* "USAGE: waspdoc check source -- Check source for new and missing.\n"
            "       waspdoc dump source <src-file> -- View source info.\n"
            "       waspdoc dump module <mod-name> -- View module info.\n")
    (exit 0))

  (define (fail . args)
    (if (null? args)
      (println* "Expected more.")
      (println* "Did not understand " @args "."))
    (exit 1))

  (define (next-opt for-what)
    (when (tc-empty? opts)
      (println* "Expected " what ".")
      (exit 1))

    (set! opt (tc-next! opts))
    opt)

  (define (parse-global-options)
    (until (tc-empty? opts)
      (define opt (tc-next! opts))
      (case arg
        (("-h" "--help") (usage))
        (("-r" "--root") (set-waspdoc-root! (next-opt "WaspDoc root path")))
        (else (tc-add! args opt)))))
  
  (define (perform-command)
    (case (next-arg)
      (("check") (case (next-arg)
                   (("source") (apply check-source (tc->list args)))
                   (else (fail "check"))))
                   
      (("dump") (case (next-arg)
                  (("source") (apply dump-source (tc->list args)))
                  (("module") (apply dump-module (tc->list args)))
                  (else (fail "dump"))))
  
      ((#f) (usage))))
 
  (guard (function (catch-exit err)
           (when (eq? (error-key err) 'exit)
            (return))

           (re-error err))
    (parse-global-options)
    (perform-command)
    #t))
          
  
