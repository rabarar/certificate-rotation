/usr/local/Cellar/openssl/1.0.2t/bin/openssl s_client -connect localhost:8000 -no_ssl3 -no_ssl2 -CAfile ./CAfile.txt #| openssl x509 -text 
