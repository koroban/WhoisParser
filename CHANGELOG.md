### 3.1.0 (May 31, 2013)
* merged and adapted support for http(s) proxies by config file (thanks to chivitli <chivitli@gmail.com>)
* added autoload directives to composer.json (thanks to John Long <a@88k.us>)
* fixed typo in method name `setSpecialWhois` (thanks to chivitli <chivitli@gmail.com>)

### 3.0.0 (Apr 17, 2013)
* fixed known bug with google.cz
* improved regex, fixed bugs and code cleanup for following WHOIS templates AFNIC, .AI, .AM, .AS, .AT, .AU, .AX, .BE, .BG, .BO, .BY, .CA, .CD, .CK, COCCA, .CZ, .DE, .DK, .DZ, .EE, .EU, .FI, .FJ, .FO, .HK, IANA, .IE, .IL, .IM, .IS, .IT, .JP, .KG, .LY, .NC, Neustar, .NL, .NU, .PL, .PT, .QA, .RO, .RS, .SG, .SK, .SM, .ST, SWITCH, .TK, .TR, .TW, .UA, .UK, .UY, Verisign and .WS
* added support for IANA #146, #440, #625, #634, #670 and .NL Registrar WHOIS
* set network property in Result to null if there are no entries left
* changed some `==` to `===` in Parser.php, Result.php and many Templates
* changed some `!=` to `!==` in Parser.php, Result.php, Config.php, Socket.php and many Templates
* changed minor bugs in IANA Template
* changed include path in Parser and Result
* changed WHOIS rawdata handling - now rawdata will be stripped from HTML tags.
* changed Parser.php to remove unneeded whitespaces in htmlBlock
* changed WHOIS template Verisign to be able to switch WHOIS server and adapter
* changed WHOIS template NetworkSolutions to fit for #634
* refreshed supported TLD list in README.md
* refreshed CHANGELOG.md

### 2.0.2 (Mar 18, 2013)
* added support for IANA #113, #292, .COOP, .ID, .IE, .NC, .NU, .SG, .TK and .XN--WGBL6A
* changed own version in composer.json
* changed WHOIS template Afilias to fit for .ID
* fixed released dates in CHANGELOG.md
* refreshed supported TLD list in README.md
* refreshed CHANGELOG.md

### 2.0.1 (Mar 14, 2013)
* changed own version in composer.json
* fixed date for version 2.0.0 in CHANGELOG.md
* fixed required version of Domain Parser in composer.json
* refreshed CHANGELOG.md

### 2.0.0 (Mar 14, 2013)
###### Note: You will need the [DomainParser](https://github.com/novutec/DomainParser) version 2.0.0 and above!
* added property template to Result class
* added support to query all TLDs directly at IANA
* added support for IANA #455, .ARPA, .DZ, .FJ, .SM, .SY, .TH, .TZ, .XN--80AO21A, .XN--3E0B707E, .XN--90A3AC, .XN--LGBBAT1AD8J, .XN--MGBAAM7A8H, .XN--O3CW4H, .XN--OGBPF8FL and .XN--YGBI2AMMX
* added type to composer.json
* added DNSSEC and TYPE to .DE template
* fixed AS number look up
* changed Config lookup to tldGroup based on new DomainParser
* changed WHOIS Config to TLD instead of each SLD
* changed WHOIS template for .EE to fit for .TZ
* changed WHOIS template for IANA to fit for .ARPA
* changed WHOIS template Afilias to fit for IANA #455
* changed link to changelog in README.md
* refreshed supported TLD list in README.md
* refreshed CHANGELOG.md

### 1.3.1 (Mar 11, 2013)
* added composer.json
* added CHANGELOG.md for faster lookup on changes
* added support for .LY, .MD, .NAME, .NAME Registrar WHOIS and .RO
* fixed namespace typo for DomainParser by [bedemiralp](http://github.com/bedemiralp)
* changed WHOIS template Afilias to fit for .NAME
* refreshed supported TLD list in README.md

### 1.3.0 (Feb 01, 2013)
* added support for IANA #9, #30, #52, #66, #85, #88, #91, #106, #140, #228, #240, #291, #320, #363, #378, #380, #401, #430, #886, #913, #931, #996, #1376, #1448, #1454, #1505
* added support for .PR, .PS, .PT, .TN, .UG, .UY, .VE and .XN--WGBL6A
* removed ICANN IDN test domain names from todo list
* fixed PHP Warning in .SK template
* changed WHOIS template MelbourneIT to fit for IANA #140
* changed WHOIS template Afilias to fit for IANA #85, #88, #240
* changed WHOIS template NetworkSolutions to fit for IANA #30, #52, #886 and #996
* changed description of WHOIS Parser in README.md

### 1.2.4 (Jan 29, 2013)
* added WHOIS template for Vautron (IANA #1443), .HM, .ST and .UA
* changed WHOIS template Key-Systems (IANA #269) to fit for Webagentur.at (IANA #648), RegistryGate (IANA #1328), 1API (IANA #1387), united-domains (IANA #1408) InterNetworX (IANA #1420) and Novutec
* renamed WHOIS template Key-Systems to rrpproxy
* removed now unused templates InternetWire, InterNetworX, 1API and united-domains
* fixed bug in Verisign template that all domain names were signed DNSSEC
* refreshed supported TLD list in README.md

### 1.2.3 (Jan 21, 2013)
* added IANA IDs to WHOIS configuration
* added IANA IDs to README.md
* added WHOIS template for .SK, Tucows (IANA #69) and Webagentur.at (IANA #648)
* changed slightly Network Solutions (IANA #2) template to fit for Tucows (IANA #69) as well
* fixed typos in README.md
* refreshed supported TLD list in README.md

### 1.2.2 (Jan 17, 2013)
* fixed CentralNic (.COM.DE) it is using .DE template instead of the standard CentralNic template
* fixed Afilias template - if domain name was not available DNSSEC flag was set
* fixed Network Solutions template to work better with different international addresses and to fill in the admin contact

### 1.2.1 (Jan 03, 2013)
###### Note: You will need the [DomainParser](https://github.com/novutec/DomainParser) version 1.1.5 and above!
* fixed phpDoc `postProcess` in several WHOIS template
* fixed WHOIS template for .AS to filter nameserver and ip addresses
* fixed WHOIS template for Verisign to parse DNSSEC for .TV, .CC and .JOBS
* added WHOIS template for .BR, .ES, .INT, .KR and Novutec
* added WHOIS servers to whois.ini for new templates
* changed WHOIS config for direct CoCCA based TLDs because WHOIS template switched to Afilias
* refreshed supported TLD list in README.md

### 1.2.0 (Dec 31, 2012)
###### Note: You will need the [DomainParser](https://github.com/novutec/DomainParser) version 1.1.5 and above!
* fixed WHOIS template for .NL and .IT, now it is working with public and registrar WHOIS
* fixed WHOIS template for .EDU
* added `setDateFormat` method to Parser to set date format for WHOIS output
* added `cleanUp` method to Result
* added `formatDate` method to Result
* added WHOIS template for .AC, .AI, .AX, .BG, .CD, .CK, .IM, .IO, .JP, .KG, .LT, .MX, .OM, .QA, .SH, .TM and Network Solutions
* added WHOIS servers to whois.ini for new templates
* added HTTP adapter to Parser
* cleaned up Parser and moved some stuff to `cleanUp` method in Result
* changed HTTP adapter
* changed copyright to 2013
* changed documentation and description in README.md
* refreshed supported TLD list in README.md

### 1.1.6 (Nov 30, 2012)
###### Note: You will need the [DomainParser](https://github.com/novutec/DomainParser) version 1.1.5 and above!
* fixed WHOIS template for .HK for IDN support
* added support for IDN top level domain names (.xn--45brj9c, .xn--fiqs8s, .xn--fiqz9s, .xn--j6w193g, .xn--fpcrj9c3d, .xn--gecrj9c, .xn--h2brj9c, .xn--kprw13d, .xn--kpry57d, .xn--mgbbh1a71e, .xn--s9brj9c and .xn--xkc2dl3a5ee0h)
* added WHOIS templates for .HU.NET, .PW, .RS, .SX, .UK and Cronon
* added WHOIS servers to whois.ini for new templates
* formatted code for WHOIS template Adamsnames and .FO
* refreshed supported TLD list in README.md

### 1.1.5 (Nov 29, 2012)
* added WHOIS templates for .FI, .FO, .GD, .IQ, .TC and .VG
* added WHOIS servers to whois.ini for .FI, .FO, .GD, .IQ, .TC and .VG
* changed Afilias template to match registration status of .IQ domain names
* refreshed supported TLD list in README.md

### 1.1.4 (Sep 05, 2012)
* added gTLD WHOIS templates for CoreNic, Gandi, Hetzner, Onamae, Variomedia, Xinnet
* added WHOIS servers to whois.ini for new templates
* added nameservers to Verisign template, will be overwritten by registrar nameservers if present in their WHOIS
* changed Afilias template to match CoreNic zone handles
* refreshed supported gTLD list in README.md

### 1.1.3 (Sep 04, 2012)
* added WHOIS templates for .EE, .IL, .IR, .KZ and .LV
* added WHOIS servers to whois.ini for .EE, .IL, .IR, .KZ and .LV
* fixed availability regex at .NZ template
* refreshed supported TLD list in README.md

### 1.1.2 (Sep 04, 2012)
* added WHOIS template for .NZ
* added WHOIS servers to whois.ini to skip querying IANA
* added boolean `parsedContacts` property to `Result` to indicate if contacts have been parsed
* changed Exception handling, if `throwException` is false it will return only the Exception message instead of the whole Exception
* fixed availability regex at Afilias template
* refreshed supported TLD list in README.md

### 1.1.1 (Sep 04, 2012)
* changed workflow, ip addresses will be queried by IANA directly and TLDs will be looked up at the config first
* changed some phpDoc
* fixed overwritten parsed query if exception was thrown
* fixed calling `lookup()` with no query
* fixed `ucfirst()` in AbstractException
* removed unused NoWhoisException

### 1.1.0 (Jul 07, 2012)
* added `dirname(__FILE__)` to require_once of classes
* added support for looking up AS numbers at IANA and RIRs
* added support for looking up top-level domain names at IANA
* added more comments to Parser.php and Result.php for better understanding
* changed `Result` properties to camelCase
* changed `AbstractException::factory()` if specific Exception is not available it will use the default Novutec Exception
* changed format and added details in README.md
* changed phpDoc description in Parser.php
* fixed bug by outputting XML with string values
* fixed bug by outputting Array with a network object
* fixed bug by calling `Registrar->toArray()` method if there isn't a registrar
* fixed bug by parsing with IP addresses

### 1.0.0 (Jul 06, 2012)
* Initial commit
