# reconftw

## tl;dr

- Requires [Go](https://golang.org/dl/)
- install.sh uses apt for installing packages, modify for your needs

```bash
git clone https://github.com/six2dez/reconftw
cd reconftw
chmod +x *.sh
./install.sh
./reconftw.sh -d target.com -a
```
![Banner](banner.png)

## Summary

**Important: run install.sh script or set your tools path in the script in $tools var (line 10)**

This is a simple script intended to perform a full recon on an objective with multiple subdomains. It performs multiples steps listed below:

0. Tools checker
1. Google Dorks (based on deggogle_hunter)
2. Subdomain enumeration (passive, resolution, bruteforce and permutations)
3. Sub TKO (subjack and nuclei)
4. Probing (httpx)
5. Websscreenshot (aquatone)
6. Template scanner (nuclei)
7. Port Scan (naabu)
8. Url extraction (waybackurls and gau)
9. Pattern Search (gf and gf-patterns)
10. Param discovery (paramspider and arjun)
11. XSS (Gxss and dalfox)
12. Github Check (git-hound)
13. Favicon Real IP (fav-up)
14. Javascript Checks (JSFScan.sh)
15. Directory fuzzing/discovery (dirsearch and ffuf)
16. Cors (CORScanner)
17. SSL Check (testssl)

Also you can perform just subdomain scan, webscan or google dorks. Remember webscan needs target lists with -l flag.

It generates and output in Recon/ folder with the name of the target domain, for example Recon/target.com/

## Installation

Run install.sh and it will install all the tools needed.

## Usage

### Full scan:
```bash
./reconftw.sh -d target.com -a
```

### Subdomains scan:
```bash
./reconftw.sh -d target.com -s
```

### Web scan (target list required):
```bash
./reconftw.sh -d target.com -l targets.txt -w
```

### Dorks:
```bash
./reconftw.sh -d target.com -g
```

## Notes

- Some tools in this script need or can use multiple API keys, such as amass, subfinder, or git-hound. It is up to you to configure them correctly, consult the documentation of each tool to do it correctly.

- This script uses dalfox with blind-xss option, you must change to your own server, check xsshunter.com.

## Short-term improvement plan:
- [ ] Enhance this Readme
- [ ] Customize output folder
- [ ] Interlace usage
- [ ] Notification support (Slack, Discord and Telegram)
- [ ] CMS tools (wpscan, drupwn/droopescan, joomscan)
- [ ] Any other interesting suggestion
- [ ] Add menu option for every feature
- [ ] Crawler
- [ ] Arch based installer support

## Thanks
For their great feedback, support, help or for nothing special but well deserved:
- [@detonXX](https://twitter.com/detonXX)
- [@cyph3r_asr](https://twitter.com/cyph3r_asr)
- [@h4ms1k](https://twitter.com/h4ms1k)


