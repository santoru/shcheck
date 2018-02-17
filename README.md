# Security Header Check
## Just check security headers on a target website

I did this tool to help me to check which security headers are enabled on certain websites.

The tool is very simple and it's the result of few minutes of coding.

It just check headers and print a report about which are enabled and which not

I think there is a lot to improve, and I will be grateful if somebody wants to help :)

```
Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  Set a custom port to connect to
  -c COOKIE_STRING, --cookie=COOKIE_STRING
                        Set cookies for the request
  -d, --disable-ssl-check
                        Disable SSL/TLS certificate validation
  -g, --use-get-method  Use GET method instead HEAD method
  -i, --information     Display information headers
  -x, --caching         Display caching headers
  --proxy=PROXY_URL     Set a proxy (Ex: http://127.0.0.1:8080)
```
### Expected output:
<p align="center">
<img src="screenshot.png" alt="Output on Facebook" />
</p>
