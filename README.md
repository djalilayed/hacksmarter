## commands used on Hack Smarter lab Aftermath https://www.hacksmarter.org/courses/27b0ac4a-5e03-4e43-afae-7c730b7b6263
```
nmap -Pn -p- --min-rate 1200 -T4 10.1.221.119
```
```
ffuf -w /home/jalil/Documents/Hackthebox/directory-list-2.3-medium.txt \
    -u http://10.1.221.119/FUZZ \
    -ic -fc 404
```
```
smtp-user-enum -U names.txt  10.1.165.36 25
```
```
for start in {1..499..18}; do
    end=$((start + 17))

    sed -n "${start},${end}p" names.txt |
    awk '
        BEGIN { printf "EHLO test.local\r\n" }
        { printf "VRFY %s\r\n", $0 }
        END { printf "QUIT\r\n" }
    ' |
    nc -w 15 10.1.221.119 25 |
    grep '^252'
done
```

