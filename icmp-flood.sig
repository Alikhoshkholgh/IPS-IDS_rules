drop icmp any any -> any any (msg:"ICMP flood ddos attack detected"; flow:to_server; threshold: type threshold, track by_dst, count 10000, seconds 5; classtype:ddos; sid:105; rev:1;)
