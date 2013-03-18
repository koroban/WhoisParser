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
 * Template for .TK
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Tk extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Organisation:\n(.*?)(?=Domain Nameservers)/is', 
            2 => '/Domain registered:(?>[\x20\t]*)(.*?)$/is', 
            3 => '/Domain Nameservers:\n(?>[\x20\t]*)(.*?)(?=Domain registered)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/Organisation:(.*?)$/is' => 'contacts:owner:address'), 
            2 => array('/Domain registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Record will expire on:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            3 => array('/[^Domain servers in listed order](?>[\x20\t]*)(.*)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Invalid query or domain name not known in/i';

    /**
     * After parsing do something
     *
     * Fix address and namesever
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        $filteredNameserver = array();
        $filteredIps = array();
        
        if (is_array($ResultSet->nameserver)) {
            foreach ($ResultSet->nameserver as $key => $line) {
                $line = strtolower(trim($line));
                if ($line != '') {
                    preg_match('/([a-z0-9\.]+)(?>[\x20\t]*)([a-z0-9\.]+)?/i', $line, $matches);
                    
                    if (isset($matches[1])) {
                        $filteredNameserver[] = $matches[1];
                    }
                    
                    if (isset($matches[2])) {
                        $filteredIps[] = $matches[2];
                    }
                }
            }
            
            if (sizeof($filteredIps) > 0) {
                $ResultSet->ips = $filteredIps;
            }
            
            $ResultSet->nameserver = $filteredNameserver;
        }
        
        if (isset($ResultSet->contacts->owner[0]->address)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->owner[0]->address)));
            
            $ResultSet->contacts->owner[0]->organization = $filteredAddress[0];
            $ResultSet->contacts->owner[0]->name = $filteredAddress[1];
            $ResultSet->contacts->owner[0]->city = $filteredAddress[3];
            $ResultSet->contacts->owner[0]->state = $filteredAddress[4];
            $ResultSet->contacts->owner[0]->country = $filteredAddress[5];
            $ResultSet->contacts->owner[0]->phone = str_replace('Phone: ', '', $filteredAddress[6]);
            $ResultSet->contacts->owner[0]->fax = str_replace('Fax: ', '', $filteredAddress[7]);
            $ResultSet->contacts->owner[0]->email = str_replace('E-mail: ', '', $filteredAddress[8]);
            $ResultSet->contacts->owner[0]->address = $filteredAddress[2];
        }
    }
}