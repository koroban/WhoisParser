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
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * Template for .COOP
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Coop extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain ID:(?>[\x20\t]*)(.*?)(?=Contact Type)/is', 
            2 => '/Contact Type:(?>[\x20\t]*)(.*?)(?=Contact Type|$)/is', 
            3 => '/Host ID:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Domain Status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^Created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Last updated:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Sponsoring registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Sponsoring registrar ID:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            
            2 => array('/Contact Type:(?>[\x20\t]*)(.+)$/im' => 'contacts:reservedType', 
                    '/Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/Organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/Street[0-9]{1}:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/City:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/State\/Province:(?>[\x20\t]*)(.+)$/im' => 'contacts:state', 
                    '/Postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/Voice:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:email'), 
            3 => array('/Host Name:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No domain records were found to match/i';

    /**
     * After parsing ...
     *
     * Move the attribute registrant to owner
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->registrant)) {
            $ResultSet->contacts->owner = $ResultSet->contacts->registrant;
            unset($ResultSet->contacts->registrant);
        }
    }
}