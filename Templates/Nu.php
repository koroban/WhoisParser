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
    protected $blocks = array(1 => '/technical contact:(.*?)(?=Record last updated)/is', 
            2 => '/record last updated on (.*?)(?=domain servers in listed order)/is', 
            3 => '/domain servers in listed order:\n(?>[\x20\t]*)(.*?)(?=owner and administrative)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/technical contact:(.*?)$/is' => 'contacts:tech:address'), 
            2 => array('/record last updated on(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/record expires on(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/record created on(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/record status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/registrar of record:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/referral url:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'), 
            3 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+)(.+)(?>[\x20\t]+).+$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+).+(?>[\x20\t]+)(.+)$/im' => 'ips'));

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
     * Fix contact address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->tech[0]->address)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->tech[0]->address)));
            
            preg_match('/(?>[\x20\t]*)([a-z0-9\.\-, ]*)(?>[\x20\t]{1,})(.*@.*)/i', $filteredAddress[0], $matches);
            
            $ResultSet->contacts->tech[0]->name = $matches[1];
            $ResultSet->contacts->tech[0]->email = $matches[2];
            
            $ResultSet->contacts->tech[0]->organization = $filteredAddress[1];
            $ResultSet->contacts->tech[0]->city = $filteredAddress[3];
            $ResultSet->contacts->tech[0]->country = $filteredAddress[4];
            
            if (sizeof($filteredAddress) === 7) {
                $ResultSet->contacts->tech[0]->country = $filteredAddress[5];
            }
            
            preg_match('/Phone: ([0-9\-\+\.\/\(\) ]*)(?>[\x20\t]*)\(voice\)(?>[\x20\t]*)([ 0-9\-\+\.\/\(\)]*)\(fax\)/i', end($filteredAddress), $matches);
            
            $ResultSet->contacts->tech[0]->phone = $matches[1];
            $ResultSet->contacts->tech[0]->fax = $matches[2];
            
            $ResultSet->contacts->tech[0]->address = $filteredAddress[2];
        }
    }
}