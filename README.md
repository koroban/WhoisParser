Novutec WHOIS Parser
====================

Lookup domain names, IP addresses and AS numbers by WHOIS.

Automatically follows the WHOIS registry referral chains until it finds the
correct WHOIS for the most complete WHOIS data. Exceptionally robust WHOIS parser
that parses a variety of free form WHOIS data into well-structured data that your
application may read. Also returns an indication of whether a domain is available.

Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
Licensed under the Apache License, Version 2.0 (the "License").

Installation
------------

Installing from source: `git clone git://github.com/novutec/WhoisParser.git` or [download the latest release](https://github.com/novutec/WhoisParser/zipball/master)

See Novutec Domain Parser (http://github.com/novutec/DomainParser) or [download the latest release](https://github.com/novutec/DomainParser/zipball/master) and install it as well.

Move the source code to your preferred project folder.

Usage
-----

* Include Parser.php
```
require_once 'DomainParser/Parser.php';
require_once 'WhoisParser/Parser.php';
```

* Create Parser() object
```
$Parser = new Novutec\WhoisParser\Parser();
```

* Call lookup() method
```
$result = $Parser->lookup($domain);
$result = $Parser->lookup($ipv4);
$result = $Parser->lookup($ipv6);
$result = $Parser->lookup($asn);
```

* Access WHOIS record, the object oriented way.
```
echo $Result->created; // get create date of domain name
print_r($Result->rawdata); // get raw output as array
```

* You may choose 5 different return types. the types are array, object, json, serialize and
xml. By default it is object. If you want to change that call the format method before calling
the parse method or provide to the constructer.
```
$Parser->setFormat('json');
$Parser = new Novutec\WhoisParser\Parser('json');
```

* You may set your own date format if you like. Please check http://php.net/strftime for further
details
```
$Parser->setDateFormat('%d.%m.%Y %H:%M:%S');
```

* If you have special WHOIS server or login credentials for a registrar WHOIS you may use
the method setSpecialWhois(). Please note that if you have a special WHOIS and the WHOIS output
looks different you need your own template.
```
$Parser->setSpecialWhois(array('it' => array('server' => 'whois.nic.it', 'port' => 43,
'format' => '-u username -w passsword %domain%', 'template' => 'it-your-own-template')));
```

ToDos
-----
* Caching of data for better performance and to reduce requests
* Change HTTP Adapter to use GET/POST
* Change Socket Adapter to be able to use Socks to split requests.

Known bugs to be fixed in further versions
------------------------------------------
* [Template] gTLD cps-datensysteme - need caching for testing, because after 5 requests you get blocked
* [Template] .BJ - recursive lookup for handles

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
[x] AI
[ ] AL
[x] AM
[ ] AN
[ ] AO
[ ] AQ
[ ] AR - webbased
[x] ARPA
[x] AS
[x] ASIA
[x] AT
[x] AU
[ ] AW
[x] AX
[ ] AZ - webbased
[ ] BA - webbased
[ ] BB - webbased with captcha
[ ] BD
[x] BE
[ ] BF
[x] BG
[ ] BH
[x] BI
[x] BIZ
[ ] BJ - need recursive calls for handles
[ ] BM - webbased
[ ] BN
[x] BO
[x] BR
[ ] BS - webbased
[ ] BT
[ ] BV - no domains but it is NORID
[ ] BW
[x] BY
[x] BZ
[x] CA
[x] CAT
[x] CC
[x] CD
[ ] CF
[ ] CG - webbased with captcha
[x] CH
[ ] CI - need recursive calls for handles
[x] CK
[ ] CL - possible
[x] CM
[x] CN
[x] CO
[x] COM
[x] COOP
[ ] CR
[ ] CU
[ ] CV
[ ] CW
[x] CX
[ ] CY
[x] CZ
[x] DE
[x] DE Registrar WHOIS
[ ] DJ
[x] DK
[x] DM
[ ] DO - whois.nic.do is broken
[x] DZ
[x] EC
[x] EDU
[x] EE
[ ] EG
[ ] ER
[x] ES
[ ] ET
[x] EU
[x] FI
[x] FJ
[ ] FK
[x] FM
[x] FO
[x] FR
[ ] GA
[ ] GB
[x] GD
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
[ ] GT  - webbased
[ ] GU
[ ] GW
[x] GY
[x] HK
[x] HM
[x] HN
[ ] HR - possible
[x] HT
[ ] HU - webbased with captcha
[x] ID
[x] IE
[X] IL
[x] IM
[x] IN
[x] INFO
[x] INT
[x] IO
[x] IQ
[X] IR
[X] IS
[x] IT
[x] IT Registrar WHOIS
[x] JE
[ ] JM
[ ] JO
[x] JOBS
[x] JP
[x] KE
[x] KG
[ ] KH
[x] KI
[ ] KM
[ ] KN
[ ] KP
[x] KR
[ ] KW
[ ] KY
[x] KZ
[x] LA
[ ] LB
[x] LC
[x] LI
[ ] LK (whois.nic.lk)
[ ] LR
[ ] LS
[x] LT
[x] LU
[x] LV
[x] LY
[ ] MA - possible
[ ] MC
[x] MD
[x] ME
[x] MG
[ ] MH
[ ] MIL - useless
[ ] MK
[ ] ML
[ ] MM
[x] MN
[ ] MO - near useless, better whois webbased but with captcha
[x] MOBI
[ ] MP - whois on port 43 broken
[ ] MQ
[ ] MR
[x] MS
[ ] MT (whois.nic.org.mt) with captcha
[x] MU
[x] MUSEUM
[ ] MV
[ ] MW
[x] MX
[ ] MY - possible
[ ] MZ
[x] NA
[x] NAME
[x] NAME Registrar WHOIS
[x] NC
[ ] NE
[x] NET
[x] NF
[x] NG
[ ] NI
[x] NL
[x] NL Registrar WHOIS
[ ] NO - possible - need recursive lookup for nameserver
[ ] NP
[ ] NR
[x] NU
[x] NZ
[x] OM
[x] ORG
[ ] PA
[x] PE
[ ] PF
[ ] PG
[ ] PH
[ ] PK - webbased
[x] PL
[x] PM
[ ] PN
[x] PR
[x] PRO
[x] PS
[x] PT
[x] PW
[ ] PY
[x] QA
[x] RE
[x] RO
[x] RS
[ ] RU - possible
[ ] RW
[ ] SA - possible
[x] SB
[x] SC
[ ] SD
[ ] SE - possible
[x] SG
[x] SH
[ ] SI - possible
[ ] SJ - no domains but it is NORID
[x] SK
[ ] SL
[x] SM
[ ] SN - whois on port 43 broken
[x] SO
[ ] SR
[x] ST
[ ] SU - possible -> RU
[ ] SV
[x] SX
[x] SY
[ ] SZ
[x] TC
[ ] TD
[x] TEL
[x] TF
[ ] TG
[x] TH
[ ] TJ
[x] TK
[x] TL
[x] TM
[x] TN
[ ] TO - useless
[ ] TP
[x] TR
[x] TRAVEL
[ ] TT - webbased
[x] TV
[x] TW
[x] TZ
[x] UA
[x] UG
[x] UK
[x] US
[x] UY
[ ] UZ - possible
[ ] VA
[x] VC
[x] VE
[x] VG
[ ] VI
[ ] VN
[ ] VU
[x] WF
[x] WS
[x] XN--3E0B707E - .kr
[x] XN--45BRJ9C - .in
[x] XN--80AO21A - .kz
[x] XN--90A3AC - .rs
[ ] XN--CLCHC0EA0B2G2A9GCD - possible .sg
[x] XN--FIQS8S - .cn
[x] XN--FIQZ9S - .cn
[x] XN--FPCRJ9C3D - .in
[ ] XN--FZC2C9E2C - .lk
[x] XN--GECRJ9C - .in
[x] XN--H2BRJ9C - .in
[ ] XN--HGBK6AJ7F53BBA
[ ] XN--HLCJ6AYA9ESC7A
[x] XN--J6W193G - .hk
[x] XN--KPRW13D - .tw
[x] XN--KPRY57D - .tw
[x] XN--LGBBAT1AD8J - .dz
[x] XN--MGBAAM7A8H - .ae
[ ] XN--MGBAYH7GPA - .jo
[x] XN--MGBBH1A71E - .in
[ ] XN--MGBC0A9AZCG - .ma
[ ] XN--MGBERP4A5D4AR - possible .sa
[x] XN--O3CW4H - .th
[x] XN--OGBPF8FL - .sy
[ ] XN--P1AI - possible .ru
[ ] XN--PGBS0DH - .tn
[x] XN--S9BRJ9C - .in
[ ] XN--WGBH1C - .eg
[x] XN--WGBL6A - .qa
[ ] XN--XKC2AL3HYE2A -.lk
[x] XN--XKC2DL3A5EE0H - .in
[x] XN--YFRO4I67O - .sg
[x] XN--YGBI2AMMX - .ps
[x] XXX
[ ] YE
[x] YT
[ ] ZA - webbased whois.co.za
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

gTLDs and thin registries sort by IANA ID (http://www.iana.org/assignments/registrar-ids/registrar-ids.xml)
```
[x] 2 (Network Solutions, LLC)
[x] 9 (Register.com, Inc.)
[x] 13 (Melbourne IT, Ltd)
[x] 15 (CORE Internet Council of Registrars)
[x] 30 (NameSecure LLC)
[x] 48 (eNom, Inc.)
[x] 49 (GMO Internet, Inc. d/b/a Onamae.com)
[x] 52 (Hostopia.com Inc. d/b/a Aplus.net)
[ ] 65 (DomainPeople, Inc.)
[x] 66 (Enameco, LLC)
[x] 69 (Tucows Domains Inc.)
[x] 79 (Easyspace Limited)
[x] 81 (Gandi SAS)
[x] 83 (1&1 Internet AG)
[x] 85 (EPAG Domainservices GmbH)
[x] 88 (Namebay SAM)
[x] 91 (007Names, Inc.)
[x] 106 (Ascio Technologies, Inc. - Denmark)
[x] 113 (CSL Computer Service Langenbach GmbH d/b/a joker.com)
[ ] 120 (Xin Net Technology Corporation)
[x] 131 (Total Web Solutions Limited trading as TotalRegistrations)
[x] 140 (Acens Technologies, S.L.U.)
[x] 141 (Cronon AG)
[x] 146 (GoDaddy.com, LLC)
[x] 151 (PSI-USA, Inc. dba Domain Robot)
[x] 226 (Deutsche Telekom AG)
[x] 228 (Moniker Online Services LLC)
[x] 240 (PlanetDomain Pty Ltd)
[x] 269 (Key-Systems GmbH)
[x] 291 (DNC Holdings, Inc.)
[x] 292 (MarkMonitor Inc.)
[x] 320 (TLDS L.L.C. d/b/a SRSPlus)
[x] 363 (Funpeas Media Ventures, LLC dba DomainProcessor.com)
[x] 378 (2030138 Ontario Inc. dba NamesBeyond.com and dba GoodLuckDomain.com)
[x] 380 (Tuonome.it Srl d/b/a APIsrs.com)
[x] 401 (Misk.com, Inc.)
[x] 430 (Net Searchers International Ltd.)
[x] 440 (Wild West Domains, LLC)
[x] 455 (EnCirca, Inc.)
[ ] 471 (Bizcn.com, Inc.)
[x] 625 (Name.com LLC)
[x] 634 (NetTuner Corp. dba Webmasters.com)
[x] 648 (Webagentur.at Internet Services GmbH d/b/a domainname.at)
[x] 670 ($$$ Private Label Internet Service Kiosk, Inc. dba "PLISK.com")
[x] 828 (Hetzner Online AG)
[x] 886 (Domain.com, LLC)
[x] 913 (PocketDomain.com Inc.)
[x] 931 (UdomainName.com LLC)
[x] 996 (DomainAdministration.com, LLC)
[x] 1040 (Dynamic Network Services, Inc.)
[x] 1239 (CPS-Datensysteme GmbH)
[x] 1257 (Variomedia AG dba puredomain.com)
[x] 1328 (RegistryGate GmbH)
[x] 1376 (Instra Corporation Pty Ltd.)
[x] 1387 (1API GmbH)
[x] 1408 (united-domains AG)
[x] 1420 (InterNetworX Ltd. & Co. KG)
[x] 1443 (Vautron Rechenzentrum AG)
[x] 1448 (Blacknight Internet Solutions Ltd.)
[x] 1454 (Nics Telekomünikasyon Ticaret Ltd. Şti.)
[x] 1505 (Gransy s.r.o. d/b/a subreg.cz)
[x] Novutec Inc.
```

3rd Party Libraries
-------------------
We are using our own Domain Parser:
* Novutec: http://github.com/novutec/DomainParser (Version 2.0.0 and above)

ChangeLog
---------
See ChangeLog at https://github.com/novutec/WhoisParser/blob/master/CHANGELOG.md

Issues
------
Please report any issues via https://github.com/novutec/WhoisParser/issues

LICENSE and COPYRIGHT
-----------------------
Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
