# mini-ctf
A mini ctf prepaired for school purposes

Vulnerabilities:
* To get admin
  - Steal password using sqli, `' UNION SELECT 1,password FROM user WHERE '1'='1' OR '1'='1`
  - Steal cookie using XSS ``
  - sqli to login without password, `' OR '1'='1`

