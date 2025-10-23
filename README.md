# jawn_parser

If you're like me and you've been working here for like, five years, you know how irritating it can be to parse 
out scan files. Probably one of the main reasons why I drink too much and make a fool of myself in front of my friends.

I'm here to help you. I want your life to be better.

This tool will take ANY Nessus, Qualys, or Nmap XML output (read: .nessus files) and slam them into a nice, conditional
format-laden, stylized excel sheet. It'll even parse out internal and external scans into separate sheets.

### Installation
- Install Python v3.7 or higher - https://www.python.org/downloads/
- `git clone [address]`
- `cd /scan_parser`
- `pip3 install .`

### Usage
scan_parser [-h] -c CLIENT_NAME FILE [FILE1 ...]

CLIENT_NAME and FILE(s) are required.

### TODO

Parse Burp Requests/Responses and handle base64 encoding where needed.