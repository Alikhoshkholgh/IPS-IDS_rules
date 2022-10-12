drop tcp any any -> any any (msg:"Syn flood ddos attack detected"; flow:to_server, not_established; flags:S; threshold: type threshold, track by_dst, count 10000, seconds 5; classtype:ddos; sid:100; rev:1;)

drop tcp any any -> any any (msg:"Ack flood ddos attack detected"; flow:to_server, not_established; flags:A; threshold: type threshold, track by_dst, count 10000, seconds 5; classtype:ddos; sid:101; rev:1;)

drop tcp any any -> any any (msg:"Syn-Ack flood ddos attack detected"; flow:to_server, not_established; flags:SA; threshold: type threshold, track by_dst, count 10000, seconds 5; classtype:ddos; sid:102; rev:1;)

drop tcp any any -> any any (msg:"Fin flood ddos attack detected"; flow:to_server, not_established; flags:F; threshold: type threshold, track by_dst, count 10000, seconds 5; classtype:ddos; sid:103; rev:1;)

drop tcp any any -> any any (msg:"RST flood ddos attack detected"; flow:to_server, not_established; flags:R; threshold: type threshold, track by_dst, count 10000, seconds 5; classtype:ddos; sid:104; rev:1;)
