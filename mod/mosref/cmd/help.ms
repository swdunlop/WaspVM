; Copyright (C) 2006, Ephemeral Security, LLC
; Modifications (C) 2008, Scott W. Dunlop <swdunlop@gmail.com>
; 
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

(module "mosref/cmd/help")
(import "mosref/shell")

(define-cmd "help" 
            "help [<command>]"
            (string-append
              "If no command is suppled, help will list all of the commands"
              " currently recognized by the shell, and their usage.  If a"
              " a command is supplied, help will provide more detailed"
              " information about the command.")
  
  (when (tc-empty? terms)
    (send-line "Commands: "
               (apply string-join "\n          "
                      (map mosref-cmd-usage (mosref-cmds))))
    (return))
 
  (define verb (tc-next! terms))
  (define cmd (find-mosref-cmd verb))
    
  (unless cmd (send-err "Command " (format verb) " not found."))

  (send (string-append "\n" (mosref-cmd-usage cmd) "\n\n" 
                       (mosref-cmd-info cmd) "\n\n")))

