<?php
/**
 * Novutec Domain Tools
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category   Novutec
 * @package    DomainParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for IANA #625
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Gtld_name extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
        1 => '/Domain (ID|Name)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=Registrant(\-| )ID|Name Server|Registrant (ID|Name)|Owner Organization|$)/is',
        2 => '/(Registry Registrant|Registrant|Owner)(\-| )(ID|Name|Organization)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Admin(\-| )(ID|Organization|Name)|Administrative (ID|Name|Contact (Name|ID)|Organization)|Name Server))/is',
        3 => '/(Admin|Administrative)(\-| )(ID|Name|Contact (Name|ID)|Organization)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Tech(\-| )(Name|ID|Contact (Name|ID))|Technical ID|CED ID|Name Server|Nameserver))/is',
        4 => '/(Tech|Technical)(\-| )(ID|Name|Contact (Name|ID)|Organization)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)(?=(Name Server|Nameservers|Nameserver|Billing (Name|ID)))/is',
        5 => '/(Name Server|Name Server Name|Nameservers)(?>[\x20\t]*):(?>[\x20\t]*)(.*?)$/is',
    );

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array(
            '/^(?>Domain )*(Create(d)*|Creation) (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created',
            '/^(?>Domain )*(Last )*Updated (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed',
            '/^(?>Domain )*(Registration )*(Expiration|Expiry|Expires) (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires',
            '/^Registrar(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:name',
            '/^Registrar IANA ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:id',
            '/^Registrar Abuse Contact Email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:email',
            '/^Registrar Abuse Contact Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:phone',
            '/^(?>Domain )*Status(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'status',
            '/^Whois Server(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'ask_whois',
        ),
        2 => array(
            '/^(Registry Registrant|Owner)(\-| )ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle',
            '/^(Registrant|Owner)(\-| )(Contact Name|Name)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name',
            '/^(Registrant|Owner)( Organization)*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization',
            '/^(Registrant|Owner)(\-| )(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address',
            '/^(Registrant|Owner)(\-| )City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city',
            '/^(Registrant|Owner)(\-| )State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state',
            '/^(Registrant|Owner)(\-| )Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
            '/^(Registrant|Owner)(\-| )ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
            '/^(Registrant|Owner)(\-| )Country(\/Economy)*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country',
            '/^(Registrant|Owner)(\-| )Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone',
            '/^(Registrant|Owner)(\-| )FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax',
            '/^(Registrant|Owner)(\-| )(Contact Email|Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'),
        3 => array(
            '/^(Admin|Administrative)(\-| )(Contact )?ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle',
            '/^(Admin|Administrative)(\-| )(Contact )?Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name',
            '/^(Admin|Administrative)(\-| )(Contact )?Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization',
            '/^(Admin|Administrative)(\-| )(Contact )?(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address',
            '/^(Admin|Administrative)(\-| )(Contact )?City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city',
            '/^(Admin|Administrative)(\-| )(Contact )?State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state',
            '/^(Admin|Administrative)(\-| )(Contact )?Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode',
            '/^(Admin|Administrative)(\-| )(Contact )?ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode',
            '/^(Admin|Administrative)(\-| )(Contact )?Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country',
            '/^(Admin|Administrative)(\-| )(Contact )?Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone',
            '/^(Admin|Administrative)(\-| )(Contact )?FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax',
            '/^(Admin|Administrative)(\-| )(Contact )?(Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'),
        4 => array(
            '/^(Tech|Technical)(\-| )(Contact )?ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle',
            '/^(Tech|Technical)(\-| )(Contact )?Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name',
            '/^(Tech|Technical)(\-| )(Contact )?Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization',
            '/^(Tech|Technical)(\-| )(Contact )?(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address',
            '/^(Tech|Technical)(\-| )(Contact )?City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city',
            '/^(Tech|Technical)(\-| )(Contact )?State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state',
            '/^(Tech|Technical)(\-| )(Contact )?Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode',
            '/^(Tech|Technical)(\-| )(Contact )?ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode',
            '/^(Tech|Technical)(\-| )(Contact )?Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country',
            '/^(Tech|Technical)(\-| )(Contact )?Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone',
            '/^(Tech|Technical)(\-| )(Contact )?FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax',
            '/^(Tech|Technical)(\-| )(Contact )?(Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'),
        5 => array(
            '/^(Name Server|Name Server Name|Nameservers)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver',
            '/^DNSSEC(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'dnssec'),
    );
}
