drop icmp any any -> any any (msg:"Ping of Death DOS attack detected"; dsize:>64; flow:to_server; threshold: type threshold, track by_dst, count 500, seconds 5; classtype:ddos; sid:106; rev:1;)
