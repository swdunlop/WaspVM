  �� � 
	    
	    
	    
	    
	     	 
	 
       �r��
	  
	  � � �7 �=
	  � �  � �
	  
	  � �  
	  � �   �p� �
	  ��  � � 
	  ��  � �
	   �n� � 
	  ��  ��     module mosref/cmd/fork import mosref/shell mosref/node lib/terminal bind-mosref-cmd fork fork [<window-name>] string-append ;Creates a new MOSREF console shell session that may be used $ in parallel with the current one.

 cmd-fork spawn-terminal 	tc-empty? MOSREF tc-next! 
do-with-io os-connection-input os-connection-output inner-io-func mosref-shell-console mosref-shell-node spawn 
anon-fn-46 run-mosref-shell