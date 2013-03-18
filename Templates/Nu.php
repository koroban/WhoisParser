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
 * Template for .NU
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Nu extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Technical Contact:(.*?)(?=Record last updated)/is', 
            2 => '/Record last updated on (.*?)(?=Domain servers in listed order)/is', 
            3 => '/Domain servers in listed order:\n(?>[\x20\t]*)(.*?)(?=Owner and Administrative)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Technical Contact:(.*?)$/is' => 'contacts:tech:address'), 
            2 => array('/Record last updated on(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/Record expires on(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/Record created on(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Record status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/Registrar of record:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/Referral URL:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'), 
            3 => array('/[^Domain servers in listed order](?>[\x20\t]*)(.*)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/NO MATCH for domain/i';

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
        
        if (isset($ResultSet->contacts->tech[0]->address)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->tech[0]->address)));
            
            $ResultSet->contacts->tech[0]->address = $filteredAddress;
            
            if (sizeof($ResultSet->contacts->tech[0]->address) == 6) {
                preg_match('/(?>[\x20\t]*)([a-z0-9\.\-, ]*)(?>[\x20\t]{1,})(.*@.*)/i', $filteredAddress[0], $matches);
                $ResultSet->contacts->tech[0]->name = $matches[1];
                $ResultSet->contacts->tech[0]->email = $matches[2];
                
                $ResultSet->contacts->tech[0]->organization = $ResultSet->contacts->tech[0]->address[1];
                $ResultSet->contacts->tech[0]->city = $ResultSet->contacts->tech[0]->address[3];
                $ResultSet->contacts->tech[0]->country = $ResultSet->contacts->tech[0]->address[4];
                
                preg_match('/Phone: ([0-9\-\+\.\/\(\) ]*)(?>[\x20\t]*)\(voice\)(?>[\x20\t]*)([ 0-9\-\+\.\/ \(\)]*)\(fax\)/i', $ResultSet->contacts->tech[0]->address[5], $matches);
                
                $ResultSet->contacts->tech[0]->phone = $matches[1];
                $ResultSet->contacts->tech[0]->fax = $matches[2];
                
                $ResultSet->contacts->tech[0]->address = $ResultSet->contacts->tech[0]->address[2];
            }
            
            if (sizeof($ResultSet->contacts->tech[0]->address) == 7) {
                preg_match('/(?>[\x20\t]*)([a-z0-9\.\-, ]*)(?>[\x20\t]{1,})(.*@.*)/i', $filteredAddress[0], $matches);
                $ResultSet->contacts->tech[0]->name = $matches[1];
                $ResultSet->contacts->tech[0]->email = $matches[2];
                
                $ResultSet->contacts->tech[0]->organization = $ResultSet->contacts->tech[0]->address[1];
                $ResultSet->contacts->tech[0]->city = $ResultSet->contacts->tech[0]->address[3];
                $ResultSet->contacts->tech[0]->state = $ResultSet->contacts->tech[0]->address[4];
                $ResultSet->contacts->tech[0]->country = $ResultSet->contacts->tech[0]->address[5];
                
                preg_match('/Phone: ([0-9\-\+\.\/\(\) ]*)(?>[\x20\t]*)\(voice\)(?>[\x20\t]*)([ 0-9\-\+\.\/\(\)]*)\(fax\)/i', $ResultSet->contacts->tech[0]->address[6], $matches);
                
                $ResultSet->contacts->tech[0]->phone = $matches[1];
                $ResultSet->contacts->tech[0]->fax = $matches[2];
                
                $ResultSet->contacts->tech[0]->address = $ResultSet->contacts->tech[0]->address[2];
            }
        }
    }
}