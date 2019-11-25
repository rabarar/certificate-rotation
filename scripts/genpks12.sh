cat clientCert-0.txt CAfile.txt clientKey-0.txt > pkcs12.txt
openssl pkcs12 -export -in pkcs12.txt -out pkcs.p12
