# Security Header Check
## Just check security headers on a target website

I did this tool to help me to check which security headers are enabled on certains websites.

The tool is very simple and it's the result of few minutes of coding.

It just check headers and print a report about which are enabled and which not

I think there is a lot to improve, and I will be grateful if somebody wants to help :)

```
Usage: ./shcheck.py [options] <target>

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  Set a custom port to connect to
  -d, --disable-ssl-check
                        Disable SSL/TLS certificate validation
  -i, --information     Display present information headers
```
### Expected output:
<p align="center">
<img src="screenshot.png" alt="Output on Facebook" />
</p>
