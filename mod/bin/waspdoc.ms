
(import "waspdoc/check-source")
(import "waspdoc/dump-source")

(define (main . args)
  (define opts (apply make-tc args))
  (define args (make-tc))

  (define arg #f)

  (define (exit)
    (error 'exit))

  (define (next-arg)
    (cond ((null? args) (set! arg #f))
          (else (set! arg (car args))
                (set! args (cdr args))))
    arg)
  
  (define (usage)
    (print* "USAGE: waspdoc check source -- Check source for new and missing.\n"
            "       waspdoc dump source <src-file> -- View source info.\n"
            "       waspdoc dump module <mod-name> -- View module info.\n")
    (exit 0))

  (define (fail . args)
    (if arg
      (println* "Did not understand " arg ".")
      (println* "Expected more."))
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
      (case (arg)
        (("-h" "--help") (usage))
        (("-r" "--root") (set-waspdoc-root! (next-opt "WaspDoc root path")))
        (else (tc-append! args opt)))))
  
  (define (perform-command)
    (case (next-arg)
      (("check") (case (next-arg)
                   (("source") (apply check-source args))
                   (else (fail "check"))))
                   
      (("dump") (case (next-arg)
                  (("source") (apply dump-source args))
                  (("module") (apply dump-module args))
                  (else (fail "dump"))))
  
      ((#f) (usage))))
 
  (guard (function (catch-exit err)
           (when (eq? (error-key err) 'exit)
            (return #f))

           (re-error err))
    (parse-global-options)
    (perform-command)
    #t))
          
  
