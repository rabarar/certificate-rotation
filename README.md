# certificate-rotation

RUN SERVER:
	./config_rot -host "mbp2019.local" -domains "mbp2019.local" -ip-addresses "127.0.0.1" 

RUN DIAL:
	 ./dial -host mbp2019.local
	./dial -ca-cert ../config_rot/goca.pem -ca-key ../config_rot/goca-key.pem -dynamicCerts -host "mbp2019.local" -domains "mbp2019.local" -ip-addresses "127.0.0.1"


Secret Server
 
1. mkidentity and install the identity cert into the keychain
2. RUN SECRET_SERVER:
	./secret --domains "mbp2019.local"

3. visit the url with the browser to read a QR Code: mbp2019.local/validator
	use the google authenticator to read the QR

4. RUN DIAL_SECRET: [make sure to use the serial number of the identity cert]
	./dial_secret -domains mbp2019.local -ident-serial 1927330095958490769

5. When Prompted for token, enter the token

6. THIS IS NOT PERSISTENT - NEED TO GENERATE A NEW QR CODE AND REINSTALL AS THE SECRET SALT WILL CHANGE on EACH RUN
	could use a persistent key/value store ... but this is a PoC.

