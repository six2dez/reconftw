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
-   [Features](#features)
-   [Mindmap](#mindmapworkflow)
-   [Improvement plan](#improvement-plan)
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
  - amass (```~/.config/amass/config.ini```)
  - subfinder (```~/.config/subfinder/config.yaml```)
  - git-hound (```~/.githound/config.yml```)
  - github-endpoints.py (```GITHUB_TOKEN``` env var)
  - favup (```shodan init <SHODANPAIDAPIKEY>```)
  - SSRF Server (```COLLAB_SERVER``` env var) 
  - Blind XSS Server (```XSS_SERVER``` env var) 
- This script uses dalfox with blind-xss option, you must change to your own server, check xsshunter.com.

## Usage

<pre>

<b>TARGET OPTIONS</b>
-d DOMAIN        Target domain
-l list.txt      Targets list, one per line
-x oos.txt       Exclude subdomains list (Out Of Scope)

<b>MODE OPTIONS</b>
-a               Perform all checks
-s               Full subdomains scan (Subs, tko and probe)
-g               Google dorks searches
-w               Perform web checks only without subs (-l required)
-t               Check subdomain takeover(-l required)
-i               Check all needed tools
-v               Debug/verbose mode, no file descriptor redir
-h               Show this help

<b>SUBDOMAIN OPTIONS</b>
--sp             Passive subdomain scans
--sb             Bruteforce subdomain resolution
--sr             Subdomain permutations and resolution (-l required)
--ss             Subdomain scan by scraping (-l required)

<b>OUTPUT OPTIONS</b>
-o output/path   Define output folder

</pre>

## :fire: Features :fire:

- Google Dorks ([degoogle_hunter](https://github.com/six2dez/degoogle_hunter))  
- Multiple subdomain enumeration techniques (passive, bruteforce, permutations and scraping)  
  - Passive ([subfinder](https://github.com/projectdiscovery/subfinder), [assetfinder](https://github.com/tomnomnom/assetfinder), [amass](https://github.com/OWASP/Amass), [findomain](https://github.com/Findomain/Findomain), [crobat](https://github.com/cgboal/sonarsearch), [waybackurls](https://github.com/tomnomnom/waybackurls))  
  - Bruteforce ([shuffledns](https://github.com/projectdiscovery/shuffledns))  
  - Permutations ([dnsgen](https://github.com/ProjectAnte/dnsgen))  
  - Subdomain JS Scraping ([JSFinder](https://github.com/Threezh1/JSFinder))  
- Sub TKO ([subjack](https://github.com/haccer/subjack) and [nuclei](https://github.com/projectdiscovery/nuclei))  
- Web Prober ([httpx](https://github.com/projectdiscovery/httpx))  
- Web screenshot ([aquatone](https://github.com/michenriksen/aquatone))  
- Template scanner ([nuclei](https://github.com/projectdiscovery/nuclei))  
- Port Scanner ([naabu](https://github.com/projectdiscovery/naabu))  
- Url extraction ([waybackurls](https://github.com/tomnomnom/waybackurls), [gau](https://github.com/lc/gau), [hakrawler](https://github.com/hakluke/hakrawler), [github-endpoints](https://gist.github.com/six2dez/d1d516b606557526e9a78d7dd49cacd3))  
- Pattern Search ([gf](https://github.com/tomnomnom/waybackurls) and [gf-patterns](https://github.com/1ndianl33t/Gf-Patterns))  
- Param discovery ([paramspider](https://github.com/devanshbatham/ParamSpider) and [arjun](https://github.com/s0md3v/Arjun))  
- XSS ([Gxss](https://github.com/KathanP19/Gxss) and [dalfox](https://github.com/hahwul/dalfox))  
- Open redirect ([Openredirex](https://github.com/devanshbatham/OpenRedireX))  
- SSRF ([asyncio_ssrf.py](https://gist.github.com/h4ms1k/adcc340495d418fcd72ec727a116fea2))  
- CRLF ([crlfuzz](https://github.com/dwisiswant0/crlfuzz))  
- Github ([git-hound](https://github.com/tillson/git-hound))  
- Favicon Real IP ([fav-up](https://github.com/pielco11/fav-up))  
- Javascript analysis ([LinkFinder](https://github.com/GerbenJavado/LinkFinder), scripts from [JSFScan](https://github.com/KathanP19/JSFScan.sh))  
- Fuzzing ([ffuf](https://github.com/ffuf/ffuf))  
- Cors ([Corsy](https://github.com/s0md3v/Corsy))  
- SSL tests ([testssl](https://github.com/drwetter/testssl.sh))  
- Multithread in some steps ([Interlace](https://github.com/codingo/Interlace))  
- Custom output folder (default under Recon/target.com/)  
- Run standalone steps (subdomains, subtko, web, gdorks...)  
- Polished installer compatible with most distros  
- Verbose mode  
- Update tools script  
- Raspberry Pi support  
- Docker support  
- CMS Scanner  
- Out of Scope Support  

## Mindmap/Workflow

![Mindmap](images/mindmap.png)

## Improvement plan:

These are the next features that would come soon, take a look at all our pending [features](https://github.com/six2dez/reconftw/labels/feature) and feel free to contribute:

:hourglass: Notificacion support  
:hourglass: HTML Report  
:hourglass: In Scope file support  
:hourglass: ASN/CIDR/Name allowed as target  

You can support this work buying me a coffee:

[<img src="https://cdn.buymeacoffee.com/buttons/v2/default-green.png">](https://www.buymeacoffee.com/six2dez)

## Thanks

For their great feedback, support, help or for nothing special but well deserved:
- [@detonXX](https://twitter.com/detonXX)
- [@cyph3r_asr](https://twitter.com/cyph3r_asr)
- [@h4ms1k](https://twitter.com/h4ms1k)
- [@Bileltechno](https://twitter.com/BilelEljaamii)
