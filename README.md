<h1 align="center">
  <br>
  <a href="https://github.com/six2dez/reconftw"><img src="images/banner_small.png" alt="reconftw"></a>
  <br>
  ReconFTW
  <br>
</h1>

<h4 align="center">A simple bash script for full recon</h4>

<p align="center">
  <a href="https://github.com/six2dez/reconftw/releases/tag/0.9-beta1">
    <img src="https://img.shields.io/badge/release-0.9--beta1-green">
  </a>
   </a>
  <a href="https://www.gnu.org/licenses/gpl-3.0.en.html">
      <img src="https://img.shields.io/badge/license-GPL3-_red.svg">
  </a>
  <a href="https://twitter.com/Six2dez1">
    <img src="https://img.shields.io/badge/twitter-%40Six2dez1-blue">
  </a>
</p>

:construction:	 ***Warning*** :construction:	

This is a live development project, until the first stable release (1.0) it will be constantly updated in master branch, so if you have detected any bug, you can open an issue or ping me over [Telegram](https://t.me/six2dez) or [Twitter](https://twitter.com/Six2dez1) and I will try to do my best :)

# Table of Contents
-   [Summary](#summary)
-   [Installation](#installation)
-   [Usage](#usage)
-   [Features](w#fire-features-fire)
-   [Mindmap](#mindmapworkflow)
-   [Improvement plan](#hourglass-improvement-plan-hourglass)
-   [Thanks](#thanks)

## Summary

ReconFTW performs automated enumeration of subdomains via various techniques and futher scanning for vulnerabilties, to give you a potential vulns.

## Installation

- [Installation Guide](https://github.com/six2dez/reconftw/wiki)
- Requires [Golang](https://golang.org/dl/) > 1.14 installed and paths correctly set ($GOPATH,$GOROOT)

```bash
git clone https://github.com/six2dez/reconftw
cd reconftw
chmod +x *.sh
./install.sh
./reconftw.sh -d target.com -a
```

- It is highly recommended, and in some cases essential, to set your api keys or env variables:
  - amass config file(```~/.config/amass/config.ini```)
  - subfinder config file(```~/.config/subfinder/config.yaml```)
  - GitHub tokens file(```~/Tools/.github_tokens```) Recommended > 5, see how to create [here](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token)
  - favup API(```shodan init <SHODANPAIDAPIKEY>```)
  - SSRF Server var(```COLLAB_SERVER``` env var) 
  - Blind XSS Server var(```XSS_SERVER``` env var) 

## Usage

<b>TARGET OPTIONS</b>  

| Flag | Description | Example |
|------|-------------|---------|
| -d	| Target domain 	|  ./reconftw.sh -d abc.com	|
| -l  	| Targets list, one per line | ./reconftw.sh -l sites.txt |
| -x 	| Exclude subdomains list (Out Of Scope) | ./reconftw.sh -x oos.txt |


<b>MODE OPTIONS</b>  

| Flag | Description | Example |
|------|-------------|---------|
| -a	| Perform all checks	|./reconftw.sh -d abc.com -a	|
| -s 	| Full subdomains scan (Subs, tko and probe) | ./reconftw.sh -d abc.com -s |
| -w| Perform web checks only without subs (-l required) | ./reconftw.sh -d abc.com -w |
| -i  	| Check all needed tools | ./reconftw.sh -i |
| -v 	| Debug/verbose mode, no file descriptor redir | ./reconftw.sh -d abc.com -v |
| -h	| Show this help | ./reconftw.sh -h |


<b>GENERAL OPTIONS</b>  

| Flag | Description | Example |
|------|-------------|---------|
| --deep |  Deep scan (Enable some slow options for deeper scan)	|./reconftw -d abc.com -a --deep	|
| --fs |  Full scope (Enable widest scope *domain* options) | ./reconftw -d abc.com -a --fs |
| -o |  Subdomain permutations and resolution (-l required) |./reconftw -d abc.com -a -o /output/here/ |

## :fire: Features :fire:

- Google Dorks ([degoogle_hunter](https://github.com/six2dez/degoogle_hunter))  
- Multiple subdomain enumeration techniques (passive, bruteforce, permutations and scraping)  
  - Passive ([subfinder](https://github.com/projectdiscovery/subfinder), [assetfinder](https://github.com/tomnomnom/assetfinder), [amass](https://github.com/OWASP/Amass), [findomain](https://github.com/Findomain/Findomain), [crobat](https://github.com/cgboal/sonarsearch), [waybackurls](https://github.com/tomnomnom/waybackurls))  
  - Certificate transparency ([crtfinder](https://github.com/eslam3kl/crtfinder) and [bufferover](tls.bufferover.run))
  - Bruteforce ([shuffledns](https://github.com/projectdiscovery/shuffledns))  
  - Permutations ([dnsgen](https://github.com/ProjectAnte/dnsgen))  
  - Subdomain JS Scraping ([JSFinder](https://github.com/Threezh1/JSFinder))  
- Sub TKO ([subjack](https://github.com/haccer/subjack) and [nuclei](https://github.com/projectdiscovery/nuclei))  
- Web Prober ([httpx](https://github.com/projectdiscovery/httpx))  
- Web screenshot ([webscreenshot](https://github.com/maaaaz/webscreenshot))  
- Template scanner ([nuclei](https://github.com/projectdiscovery/nuclei))  
- Port Scanner ([naabu](https://github.com/projectdiscovery/naabu))  
- Url extraction ([waybackurls](https://github.com/tomnomnom/waybackurls), [gau](https://github.com/lc/gau), [gospider](https://github.com/jaeles-project/gospider), [github-endpoints](https://gist.github.com/six2dez/d1d516b606557526e9a78d7dd49cacd3))  
- Pattern Search ([gf](https://github.com/tomnomnom/waybackurls) and [gf-patterns](https://github.com/1ndianl33t/Gf-Patterns))  
- Param discovery ([paramspider](https://github.com/devanshbatham/ParamSpider) and [arjun](https://github.com/s0md3v/Arjun))  
- XSS ([XSStrike](https://github.com/s0md3v/XSStrike))  
- Open redirect ([Openredirex](https://github.com/devanshbatham/OpenRedireX))  
- SSRF ([asyncio_ssrf.py](https://gist.github.com/h4ms1k/adcc340495d418fcd72ec727a116fea2))  
- CRLF ([crlfuzz](https://github.com/dwisiswant0/crlfuzz))  
- Github ([GitDorker](https://github.com/obheda12/GitDorker))  
- Favicon Real IP ([fav-up](https://github.com/pielco11/fav-up))  
- Javascript analysis ([LinkFinder](https://github.com/GerbenJavado/LinkFinder), scripts from [JSFScan](https://github.com/KathanP19/JSFScan.sh))  
- Fuzzing ([ffuf](https://github.com/ffuf/ffuf))  
- Cors ([Corsy](https://github.com/s0md3v/Corsy))  
- SSL tests ([testssl](https://github.com/drwetter/testssl.sh))  
- Multithread in some steps ([Interlace](https://github.com/codingo/Interlace))  
- Custom output folder (default under Recon/target.tld/)  
- Run standalone steps (subdomains, subtko, web, gdorks...)  
- Polished installer compatible with most distros  
- Verbose mode  
- Update tools script  
- Raspberry Pi support  
- Docker support  
- CMS Scanner ([CMSeeK](https://github.com/Tuhinshubhra/CMSeeK))
- Out of Scope Support  
- LFI Checks  
- Notification support for Slack, Discord and Telegram ([notify](https://github.com/projectdiscovery/notify))

## Mindmap/Workflow

![Mindmap](images/mindmap.png)

## :hourglass: Improvement plan :hourglass:

These are the next features that would come soon, take a look at all our pending [features](https://github.com/six2dez/reconftw/labels/feature) and feel free to contribute:

- [X] Notification support  
- [ ] HTML Report  
- [ ] In Scope file support  
- [ ] ASN/CIDR/Name allowed as target  

You can support this work buying me a coffee:

[<img src="https://cdn.buymeacoffee.com/buttons/v2/default-green.png">](https://www.buymeacoffee.com/six2dez)

## Thanks

For their great feedback, support, help or for nothing special but well deserved:
- [@detonXX](https://twitter.com/detonXX)
- [@cyph3r_asr](https://twitter.com/cyph3r_asr)
- [@h4ms1k](https://twitter.com/h4ms1k)
- [@Bileltechno](https://twitter.com/BilelEljaamii)
