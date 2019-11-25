# certificate-rotation

RUN SERVER:
	./config_rot -host "mbp2019.local" -domains "mbp2019.local" -ip-addresses "127.0.0.1" 

RUN DIAL:
	 ./dial -host mbp2019.local
