#!/usr/bin/env python3

import urllib.request
import time

("f82606c5dde2f0e1eec388f9985e07c3" +
"a12bb7edc6ee1b27e1a651943f5883d0" +
"2e7db3481ecd021aeec04c34865d6a35" +
"e93f736279d39610b654905ecacd5e38" +
"ac284200f0f128e0f2b930481eb70506" +
"1478914b488997f64cb80aa9ce59b9ed")

def h(x):
    return "{:02x}".format(x)

for i in range(256):
    req = urllib.request.Request("http://localhost:8080/admin?ciphertext=" +
"f82606c5dde2f0e1eec388f9985e07c3" +
"a12bb7edc6ee1b27e1a651943f5883d0" +
"2e7db3481ecd021aeec04c34865d6a35" +
"e93f736279d39610b654905ecacd" + h(i) + "1b" +
"ac284200f0f128e0f2b930481eb70506"
#"ac284200f0f128e0f2b930481eb705" + h(i) +
#h(i) + "375d1fefee37ffeda62f5701a81a19" +
#"1478914b488997f64cb80aa9ce59b9ed"
)
    req.add_header("Cookie", "actix-session=Lov7F2kZtq60V+Od92eBRxyvvEvdzbRNyynpF98v4og%3D%7B%22id%22%3A%221%22%7D")
    #print(urllib.request.urlopen(req).read())
    if b"Signature successfully set" in urllib.request.urlopen(req).read():
        print(h(i))

