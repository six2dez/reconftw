# reconftw

## tl;dr

```bash
git clone https://github.com/six2dez/reconftw
cd reconftw
./reconftw.sh -d target.com -a
```
![Banner](banner.png)

## Summary

**Important: set your tools path in the script in $tools var (line 10)**

This is a simple script intended to perform a full recon on an objective with multiple subdomains. It performs multiples steps listed below:

0. Tools checker
1. Google Dorks (based on deggogle_hunter)
2. Subdomain enumeration (multiple tools: pasive, resolution, bruteforce and permutations)
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

## Short-term improvement plan:
- [ ] Enhance this Readme
- [ ] Customize output folder
- [ ] Install script
- [ ] Notification support (Slack, Discord and Telegram)
- [ ] Any other interesting suggestion
