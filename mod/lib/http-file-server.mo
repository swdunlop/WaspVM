 .j� �
	    
	    
	  � �  �-��
	  � �  �� � �,
	  ��  � �  �,
	 	 � �  � � 
�k��
�� � �  � � 
	  � �   �A�J
	    � � � �
	  
	    � � 
	  
	    � �   � �  � �  � �  
 ����
�� � �  � � 
	  � �   ���
	    � � � �
	  
	    � �  � �  � �   	����	
	  � �
	  � � ����
	  �� � �  
	  � � � �  � � ����
	  �� � �  � �
	   �� �
	  �� � � 
	  
	  � �     ��
�� 
	  � �  �
	  
	  � �     �
�� 
	  � �  ��� 
	  � �    �x��
	 ! 
	 " � �   � �
	 #  $ 
	 # 
	 % � �  
	 #  & 
	  �� � � � �
	 #  ' 
	 # 
	 % � �  
	 #  & � ��b
	 ( � �  ��  ) � ��w
	 ( � �  �� 
	   * � �   +  -  
	  ��  � �  � � � � 	 module lib/http-file-server import lib/http-server 	make-dict find-or-use-server queue? dict-ref spawn-http-file-server offer-http-file string-begins-with? / string-append send list offer Content-type:  withdraw-http-file withdraw 
make-queue do-offer 	dict-set! do-withdraw dict-remove! spawn 
anon-fn-14 wait eq? car cdr spawn-http-server 
anon-fn-21 url-path http-request-url print GET:  format 
 	File is:  write-http-response OK File Not Found:  ,� Content-type: text/plain (File not found.
Do not take internally.