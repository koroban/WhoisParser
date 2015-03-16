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
 * @namespace Novutec\Whois\Parser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for .WS
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Ws extends Regex
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
            '/^\s*(?>Domain )*(Create(d)*|Creation) (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created',
            '/^\s*(?>Domain )*(Last )*Updated (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed',
            '/^\s*(?>Domain |Registrar )*(Registration )*(Expiration|Expiry|Expires) (On|Date)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires',
            '/^\s*Registrar(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:name',
            '/^\s*Registrar URL(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:url',
            '/^\s*Registrar IANA ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:id',
            '/^\s*Registrar Abuse Contact Email(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:email',
            '/^\s*Registrar Abuse Contact Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'registrar:phone',
            '/^\s*(?>Domain )*Status(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'status',
            '/^\s*Registrar WHOIS Server(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'whoisserver',
        ),
        2 => array(
            '/^\s*(Registry Registrant|Owner)(\-| )ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle',
            '/^\s*(Registrant|Owner)(\-| )(Contact Name|Name)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name',
            '/^\s*(Registrant|Owner)( Organization)*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization',
            '/^\s*(Registrant|Owner)(\-| )(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address',
            '/^\s*(Registrant|Owner)(\-| )City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city',
            '/^\s*(Registrant|Owner)(\-| )State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state',
            '/^\s*(Registrant|Owner)(\-| )Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
            '/^\s*(Registrant|Owner)(\-| )ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
            '/^\s*(Registrant|Owner)(\-| )Country(\/Economy)*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country',
            '/^\s*(Registrant|Owner)(\-| )Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone',
            '/^\s*(Registrant|Owner)(\-| )FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax',
            '/^\s*(Registrant|Owner)(\-| )(Contact Email|Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'),
        3 => array(
            '/^\s*(Admin|Administrative)(\-| )(Contact )?ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax',
            '/^\s*(Admin|Administrative)(\-| )(Contact )?(Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'),
        4 => array(
            '/^\s*(Tech|Technical)(\-| )(Contact )?ID(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle',
            '/^\s*(Tech|Technical)(\-| )(Contact )?Name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name',
            '/^\s*(Tech|Technical)(\-| )(Contact )?Organization(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization',
            '/^\s*(Tech|Technical)(\-| )(Contact )?(Street|Address)[0-9]*(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address',
            '/^\s*(Tech|Technical)(\-| )(Contact )?City(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city',
            '/^\s*(Tech|Technical)(\-| )(Contact )?State\/Province(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state',
            '/^\s*(Tech|Technical)(\-| )(Contact )?Postal(\-| )Code(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode',
            '/^\s*(Tech|Technical)(\-| )(Contact )?ZIP(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode',
            '/^\s*(Tech|Technical)(\-| )(Contact )?Country(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country',
            '/^\s*(Tech|Technical)(\-| )(Contact )?Phone(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone',
            '/^\s*(Tech|Technical)(\-| )(Contact )?FAX(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax',
            '/^\s*(Tech|Technical)(\-| )(Contact )?(Email|E-Mail)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'),
        5 => array(
            '/^\s*(Name Server|Name Server Name|Nameservers)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver',
            '/^\s*DNSSEC(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'dnssec'),
    );

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match for/i';

    protected $rateLimit = '/You exceeded the maximum allowable number of whois lookups/i';

    /**
     * After parsing ...
     * 
     * .WS is a thin registry, therefore they only provide us some details and the
     * real whois server of the registrar for the given domain name. Therefore we have
     * to restart the process with the real whois server.
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        
        // check if registrar name is set, if not then there was an error while
        // parsing
        if (! isset($ResultSet->registrar->name)) {
            return;
        }
        
        $newConfig = $Config->get($ResultSet->whoisserver);
        
        if ($newConfig['server'] == '') {
            $newConfig['server'] = $ResultSet->whoisserver;
        }
        
        $Config->setCurrent($newConfig);
        $WhoisParser->call();
    }
}