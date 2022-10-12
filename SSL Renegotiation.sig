
drop tcp any any -> any any ( 	msg:"ET DOS SSL Renegotiation detected";flow:established; ssl_state: client_hello;content:"|14 03 01 00 01 01"; threshold: type threshold, track by_dst, count 8, seconds 1; classtype:ddos; sid:8000;)
