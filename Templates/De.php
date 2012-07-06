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
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
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
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
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
    protected $blocks = array(1 => '/domain:[\s]*(.*?)[\n]{2}/is', 
            2 => '/\[(Holder|Zone|Tech|Admin)(\-C)?\][\n](.*?)([\n]{2}|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Nserver: (.+)$/im' => 'nameserver', '/^Status: (.+)$/im' => 'status', 
                    '/^Changed: (.+)$/im' => 'changed', '/^RegAccName: (.+)$/im' => 'registrar:name', 
                    '/^RegAccId: (.+)$/im' => 'registrar:id'), 
            
            2 => array('/^\[(Holder|Zone|Tech|Admin)/i' => 'contacts:reservedType', 
                    '/^name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/^city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/^countrycode:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^email:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Status: free/i';

    /**
     * After parsing ...
     *
     * Move the attribute holder to owner
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->holder)) {
            $ResultSet->contacts->owner = $ResultSet->contacts->holder;
            unset($ResultSet->contacts->holder);
        }
    }
}