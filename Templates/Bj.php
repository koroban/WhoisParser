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
 * Template for .BJ
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Bj extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            2 => '/Person:(?>[\x20\t]*)(.*?)(?=To single out)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Last Updated:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Administrative Contact:(?>[\x20\t]*)(.+)$/im' => 'network:contact:admin', 
                    '/^Technical Contact:(?>[\x20\t]*)(.+)$/im' => 'network:contact:tech', 
                    '/^Name Server [0-9]*:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            2 => array('/^Name:(?>[\x20\t]*)(.+)$/im' => 'contact:name', 
                    '/^Email address:(?>[\x20\t]*)(.+)$/im' => 'contact:email', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contact:address', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contact:country', 
                    '/^Telephone:(?>[\x20\t]*)(.+)$/im' => 'contact:phone', 
                    '/^FAX No:(?>[\x20\t]*)(.+)$/im' => 'contact:fax', 
                    '/^Created:(?>[\x20\t]*)(.+)$/im' => 'contact:created', 
                    '/^Last Updated:(?>[\x20\t]*)(.+)$/im' => 'contact:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No records matching/i';

    /**
     * After parsing ...
     *
     * Get contact handles
     *
     * @param  object $whoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
    /**
        if (isset($ResultSet->network->contact->admin)) {
            $admin = trim($ResultSet->network->contact->admin);
            unset($ResultSet->network->contact->admin);
            $WhoisParser->call($admin);
            $ResultSet->contacts->admin = $ResultSet->contact;
        }
        
        if (isset($ResultSet->network->contact->tech)) {
            $tech = trim($ResultSet->network->contact->tech);
            unset($ResultSet->network->contact->tech);
            $WhoisParser->call($tech);
            $ResultSet->contacts->tech = $ResultSet->contact;
        }
        
        unset($ResultSet->contact);*/
    }
}