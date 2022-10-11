
alert tcp any any -> any any ( msg:"rudy check"; flow:to_server,established; flags: P+; content:"POST"; depth:4; fast_pattern; content:"Content-Length";content:"keep-alive"; flowint:rudy,notset;flowint:rudy, =, 1;noalert; classtype:ddos; sid:7000;)
alert tcp any any -> any any ( msg:"rudy suspicious"; dsize:10<>100; flags: P+;flow:to_server,established;flowint:rudy ,isset; flowint:rudy, +, 1; noalert; classtype:ddos; sid:7001;)
drop tcp any any -> any any (  msg:"rudy attack detected"; dsize:10<>100; flags: P+;flow:to_server,established;flowint:rudy,isset; flowint:rudy, >, 5; classtype:ddos; sid:7002;)
