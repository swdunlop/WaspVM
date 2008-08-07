
(define (vim-keyword-list leader items)
  (define page (make-tc))
  (define maxw (- 78 (string-length leader)))
  (define item (format (car items)))
  (define (next-item) 
    (set! item (format (car items)))
    (set! items (cdr items)))
  
  (until (null? items)
    (define line (make-string))
    (define line-full #f)

    (until (or line-full (null? items))
      (cond
        ((> (+ (string-length line) 1 (string-length item)) maxw)
         (set! line-full #t))

        (else
          (string-append! line " " item)
          (next-item))))
    
    (tc-add! page line))

  (string-join *line-sep* 
               @(map string-append (repeat leader) page)
               ""))

(define (function-definition? pair)
  (and (function? (cdr pair))
       (not (eq? (car pair) 'write-vim-syntax))))

(define (vim-syntax-lines)
  (vim-keyword-list "syn keyword waspSyntax" 
                    (map-car (list @(waspvm-special-forms) @(waspvm-syntax)))))

(define (vim-keyword-lines)
  (vim-keyword-list "syn keyword waspFunc" 
    (map-car (filter function-definition? (globals)))))

(define (write-vim-syntax path)
  (write-data-file 
    path
    (string-join *line-sep*
                 (vim-syntax-lines)
                 ""
                 (vim-keyword-lines))))

(export write-vim-syntax)

