 � � 
	    
	    
	    
	         	����
	 
   
	    
	   �|��
	  � �  � �
	  � �  �A
	  � �  � �
	  
	  � �   
	  � �  �U �V  � ��g
	    
	  � �  �h  � ��y
	    
	  � �  �z   
	      module mosref/cmd/nodes import mosref/shell mosref/node bind-mosref-cmd nodes /Lists the nodes currently known to the console. 	cmd-nodes 	send-line NODES:  string-join 
        map format-node 	node-addr node-has-port? 	node-port string-append node-id node-online  online  offline 
 address:  format-addr    port:  format list-mosref-nodes