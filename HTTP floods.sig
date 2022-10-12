
drop http any any -> any any (msg:"http-GET flood detected"; l7_protocol:http_get; flow:to_server,established; threshold: type threshold, track by_dst, count 100, seconds 5; classtype:ddos; sid:111; rev:1;)

drop http any any -> any any (msg:"http-POST flood detected"; l7_protocol:http_post; flow:to_server,established; threshold: type threshold, track by_dst, count 100, seconds 5; classtype:ddos; sid:112; rev:1;)
