Novutec WhoisParser
===================

Parse the WHOIS output by using certain templates.

Automatically follows the WHOIS registry referral chains until it finds the
correct WHOIS for the most complete WHOIS data. Exceptionally robust WHOIS parser
that parses a variety of free form WHOIS data into well-structured data that your
application may read. Also returns an indication of whether a domain is available.

Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
Licensed under the Apache License, Version 2.0 (the "License").

Installation
------------

Installing from source: `git clone git://github.com/novutec/WhoisParser.git` or [download the latest release](https://github.com/novutec/WhoisParser/zipball/master)

See Novutec DomainParser (http://github.com/novutec/DomainParser) or [download the latest release](https://github.com/novutec/DomainParser/zipball/master) and install it as well.

Move the source code to your preferred project folder.

Usage
-----

* include Parser.php
```
require_once 'DomainParser/Parser.php';
require_once 'WhoisParser/Parser.php';
```

* create Parser() object
```
$Parser = new Novutec\WhoisParser\Parser();
```

* call lookup() method
```
$result = $Parser->lookup($domain);
```

* access WHOIS record, the object oriented way.
```
echo $Result->created; // get create date of domain name
print_r($Result->rawdata); // get raw output as array
```

* you can choose 5 different return types. the types are array, object, json, serialize and
xml. by default it is object. if you want to change that call the format method before calling
the parse method or provide to the constructer. if you are not using object and an
error occurs, then exceptions will not be trapped within the response and thrown directy.
```
$Parser->setFormat('json');
$Parser = new Novutec\WhoisParser\Parser('json');
```

* if you have special whois server or login credentials for member whois you may use
the method setSepcialWhois(). Please note that if you have a special whois and the output
looks different you need your own template.
```
$Parser->setSepcialWhois('it' => array('server' => 'whois.nic.it', 'port' => 43,
'format' => '-u username -w passsword %domain%', 'template' => 'it-your-template'));
```

ToDos
-----
Caching

Known bugs to be fixed in further versions
------------------------------------------
* [Adapter] HTTP - it is just a prototype
* [Template] .NL - need caching for testing, because after 10 requests you get blocked
* [Template] .IT - no algorithm for public whois
* [Template] gTLD cps-datensysteme - need caching for testing, because after 5 requests you get blocked
* [Template] .EDU - no algorithm
* [Template] .CZ - found a strange behavior by matching the contact handles with google.cz
* [Template] .BJ - recrusive lookup for handles

Tested with following RIRs and TLDs
----------------------------------
RIRs
```
[x] Afrinic
[x] Apnic
[x] Arin
[x] Krnic
[x] Lacnic
[x] Ripe
```

ccTLDs (http://data.iana.org/TLD/tlds-alpha-by-domain.txt)
```
[x] AC
[ ] AD
[x] AE
[x] AERO
[x] AF
[x] AG
[ ] AI
[ ] AL
[x] AM
[ ] AN
[ ] AO
[ ] AQ
[ ] AR
[ ] ARPA
[x] AS
[x] ASIA
[x] AT
[x] AU
[ ] AW
[ ] AX
[ ] AZ
[ ] BA
[ ] BB
[ ] BD
[x] BE
[ ] BF
[ ] BG
[ ] BH
[x] BI
[x] BIZ
[ ] BJ - need recrusive calls for handles
[ ] BM
[ ] BN
[x] BO
[ ] BR
[ ] BS
[ ] BT
[ ] BV
[ ] BW
[x] BY
[x] BZ
[x] CA
[x] CAT
[x] CC
[ ] CD
[ ] CF
[ ] CG
[x] CH
[ ] CI - need recrusive calls for handles
[ ] CK
[ ] CL - possible
[x] CM
[x] CN
[x] CO
[x] COM
[ ] COOP - to few domain names
[ ] CR
[ ] CU
[ ] CV
[ ] CW
[x] CX
[ ] CY
[x] CZ
[x] DE
[ ] DJ
[x] DK
[x] DM
[ ] DO
[ ] DZ - whois server on port 43 is broken, http get whois possible
[x] EC
[x] EDU
[x] EE
[ ] EG
[ ] ER
[ ] ES - possible
[ ] ET
[x] EU
[ ] FI - possible
[ ] FJ
[ ] FK
[x] FM
[ ] FO - possible
[x] FR
[ ] GA
[ ] GB
[ ] GD - possible
[ ] GE
[ ] GF
[x] GG
[ ] GH
[x] GI
[X] GL
[ ] GM
[ ] GN
[ ] GOV - to few domain names
[ ] GP
[ ] GQ
[ ] GR
[x] GS
[ ] GT
[ ] GU
[ ] GW
[x] GY
[x] HK
[ ] HM
[x] HN
[ ] HR - possible
[x] HT
[ ] HU - webbased with captcha
[ ] ID
[ ] IE - possible
[X] IL
[ ] IM - possible
[x] IN
[x] INFO
[ ] INT - to few domain names
[ ] IO - webbased
[ ] IQ - possible
[X] IR
[X] IS
[x] IT
[x] JE
[ ] JM
[ ] JO
[x] JOBS
[ ] JP - possible
[x] KE
[ ] KG - possible
[ ] KH
[x] KI
[ ] KM
[ ] KN
[ ] KP
[ ] KR - possible
[ ] KW
[ ] KY
[x] KZ
[x] LA
[ ] LB
[x] LC
[x] LI
[ ] LK
[ ] LR
[ ] LS
[ ] LT - possible
[x] LU
[x] LV
[ ] LY - possible
[ ] MA - possible
[ ] MC
[ ] MD - possible
[x] ME
[x] MG
[ ] MH
[ ] MIL - useless
[ ] MK
[ ] ML
[ ] MM
[x] MN
[ ] MO
[x] MOBI
[ ] MP - whois on port 43 broken
[ ] MQ
[ ] MR
[x] MS
[ ] MT
[x] MU
[x] MUSEUM
[ ] MV
[ ] MW
[ ] MX - possible
[ ] MY - possible
[ ] MZ
[x] NA
[ ] NAME - possible
[ ] NC - possible
[ ] NE
[x] NET
[x] NF
[x] NG
[ ] NI
[x] NL
[ ] NO - possible
[ ] NP
[ ] NR
[ ] NU
[x] NZ
[ ] OM - possible
[x] ORG
[ ] PA
[x] PE
[ ] PF
[ ] PG
[ ] PH
[ ] PK
[x] PL
[x] PM
[ ] PN
[ ] PR - whois on port 43 broken
[x] PRO
[ ] PS
[ ] PT - possible
[ ] PW
[ ] PY
[ ] QA - possible
[x] RE
[ ] RO - possible
[ ] RS - possible
[ ] RU - possible
[ ] RW
[ ] SA - possible
[x] SB
[x] SC
[ ] SD
[ ] SE - possible
[ ] SG - possible
[ ] SH - webbased
[ ] SI - possible
[ ] SJ
[ ] SK - possible
[ ] SL
[ ] SM - possible
[ ] SN - whois on port 43 broken
[x] SO
[ ] SR
[ ] ST - possible
[ ] SU - possible -> RU
[ ] SV
[ ] SX - possible
[ ] SY
[ ] SZ
[ ] TC - possible
[ ] TD 
[x] TEL
[x] TF
[ ] TG
[ ] TH - possible
[ ] TJ
[ ] TK - possible
[x] TL
[ ] TM - webbased
[ ] TN - whois server on port 43 broken
[ ] TO - useless
[ ] TP
[x] TR
[x] TRAVEL
[ ] TT
[x] TV
[x] TW
[ ] TZ - possible
[ ] UA - possible
[ ] UG - possible
[ ] UK - possible
[x] US
[ ] UY - possible
[ ] UZ - possible
[ ] VA
[x] VC
[ ] VE - possible
[ ] VG - possible
[ ] VI
[ ] VN
[ ] VU
[x] WF
[x] WS
[ ] XN--0ZWM56D
[ ] XN--11B5BS3A9AJ6G
[ ] XN--3E0B707E - possible .kr
[ ] XN--45BRJ9C - don't know but it is .in
[ ] XN--80AKHBYKNJ4F
[ ] XN--80AO21A - possible .kz
[ ] XN--90A3AC - possible .rs
[ ] XN--9T4B11YI5A
[ ] XN--CLCHC0EA0B2G2A9GCD - possible .sg
[ ] XN--DEBA0AD
[ ] XN--FIQS8S - possible .cn
[ ] XN--FIQZ9S - possible .cn
[ ] XN--FPCRJ9C3D - don't know but it is .in
[ ] XN--FZC2C9E2C
[ ] XN--G6W251D
[ ] XN--GECRJ9C - don't know but it is .in
[ ] XN--H2BRJ9C - don't know but it is .in
[ ] XN--HGBK6AJ7F53BBA
[ ] XN--HLCJ6AYA9ESC7A
[ ] XN--J6W193G - possible .hk
[ ] XN--JXALPDLP
[ ] XN--KGBECHTV
[ ] XN--KPRW13D - possible .tw
[ ] XN--KPRY57D - possible .tw
[ ] XN--LGBBAT1AD8J - possible .dz
[ ] XN--MGBAAM7A8H - possible .ae
[ ] XN--MGBAYH7GPA
[ ] XN--MGBBH1A71E - don't know but it is .in
[ ] XN--MGBC0A9AZCG - don't know but it is .ma
[ ] XN--MGBERP4A5D4AR - possible .sa
[ ] XN--O3CW4H - possible .th
[ ] XN--OGBPF8FL
[ ] XN--P1AI - possible .ru
[ ] XN--PGBS0DH
[ ] XN--S9BRJ9C - don't know but it is .in
[ ] XN--WGBH1C
[ ] XN--WGBL6A - possible .qa
[ ] XN--XKC2AL3HYE2A
[ ] XN--XKC2DL3A5EE0H  - don't know but it is .in
[ ] XN--YFRO4I67O - possible sgnic
[ ] XN--YGBI2AMMX - possible .ps
[ ] XN--ZCKZAH
[x] XXX
[ ] YE
[x] YT
[ ] ZA
[ ] ZM
[ ] ZW
```

Special TLDs
```
[x] CentralNic (https://www.centralnic.com/names/domains)
[x] CO.NL
[x] CO.NO
[x] COM.CC
[x] ORG.CC
[x] EDU.CC
[x] NET.CC
```

gTLDs
```
[ ] 123-Reg.co.uk
[x] 1API
[ ] 35.com
[ ] Antagus.de
[ ] Ascio
[ ] BasicFusion.com
[ ] BizCn.com
[x] Core Nic
[ ] Corporate Domains
[x] CPS Datensysteme
[x] Deutsche Telekom
[ ] DirectNic
[ ] DomainPeople
[ ] Domainsite.com
[ ] DotRegistrar
[ ] Dotster
[ ] Dreamhost
[ ] Dynadot
[x] eNom
[ ] EPAG
[x] Gandi
[ ] GoDaddy
[x] Hetzner.de
[ ] HTTP.net
[ ] Joker.com
[ ] Fabulous.com
[ ] FastDomain.com
[x] InterNetWire
[x] InterNetworkX
[x] Key-Systems
[ ] MarkMonitor
[x] MelbourneIT
[ ] Name.com
[ ] NameKing.com
[ ] Names4ever
[ ] Namesdirect
[ ] Namesecure
[ ] Network Solutions
[ ] Nicline
[x] Onamae.com
[ ] OnlineNic
[ ] OVH
[x] PSI-USA
[ ] Register.com
[ ] Register.it
[ ] ResellerClub.com
[x] Schlund
[ ] Srsplus
[ ] Strato
[ ] Tucows
[x] united-domains
[x] Variomedia
[ ] Webnic
[ ] WildWestDomains
[x] Xinnet.com
```

3rd Party Libraries
-------------------
We are using our own DomainParser:
* Novutec: http://github.com/novutec/DomainParser

ChangeLog
---------
See ChangeLog at https://github.com/novutec/WhoisParser/wiki/ChangeLog

Issues
------
Please report any issues via https://github.com/novutec/WhoisParser/issues

LICENSE and COPYRIGHT
-----------------------
Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.