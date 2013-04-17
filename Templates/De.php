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
 * Template for .DE
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_De extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            2 => '/\[(holder|zone|tech|admin)(\-c)?\]\n(.*?)([\n]{2}|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/dnskey:(?>[\x20\t]*)(.+)$/im' => 'dnssec', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/regaccname:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/regcccid:(?>[\x20\t]*)(.+)$/im' => 'registrar:id'), 
            
            2 => array('/\[(holder|zone|tech|admin)/i' => 'contacts:reservedType', 
                    '/type:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/countrycode:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/status:(?>[\x20\t]*)free/i';

    /**
     * After parsing ...
     *
     * Move the attribute holder to owner and fix dnssec
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        if (isset($ResultSet->contacts->holder)) {
            $ResultSet->contacts->owner = $ResultSet->contacts->holder;
            unset($ResultSet->contacts->holder);
        }
    }
}