drop tcp any any -> any any (msg:"Syn flood ddos attack detected"; flow:to_server, not_established; flags:S; detection_filter: track by_dst, count 10000, seconds 5; classtype:ddos; sid:100; rev:1;)

drop tcp any any -> any any (msg:"Ack flood ddos attack detected"; flow:to_server, not_established; flags:A; detection_filter: track by_dst, count 10000, seconds 5; classtype:ddos; sid:101; rev:1;)

drop tcp any any -> any any (msg:"Syn-Ack flood ddos attack detected"; flow:to_server, not_established; flags:SA; detection_filter: track by_dst, count 10000, seconds 5; classtype:ddos; sid:102; rev:1;)

drop tcp any any -> any any (msg:"Fin flood ddos attack detected"; flow:to_server, not_established; flags:F; detection_filter: track by_dst, count 10000, seconds 5; classtype:ddos; sid:103; rev:1;)

drop tcp any any -> any any (msg:"RST flood ddos attack detected"; flow:to_server, not_established; flags:R; detection_filter: track by_dst, count 10000, seconds 5; classtype:ddos; sid:104; rev:1;)
