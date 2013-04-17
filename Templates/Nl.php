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
 * Template for .NL
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Nl extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrant|registrar)/is', 
            2 => '/registrant:(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            3 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=registrar)/is', 
            4 => '/registrar:(?>[\x20\t]*)(.*?)(?=(technical contact\(s\)|dnssec))/is', 
            5 => '/technical contact\(s\):(?>[\x20\t]*)(.*?)(?=dnssec)/is', 
            6 => '/dnssec:(?>[\x20\t]*)(.*?)(?=domain nameservers)/is', 
            7 => '/domain nameservers:(?>[\x20\t]*)(.*?)(?=(date registered|record maintained))/is', 
            8 => '/date registered:(?>[\x20\t]*)(.*?)(?=record maintained)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/registrant:\n(?>[\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array(
                    '/administrative contact:\n(?>[\x20\t]*)(.+)$/is' => 'contacts:admin:address'), 
            4 => array('/registrar:\n(?>[\x20\t]*)(.+)\n/im' => 'registrar:name'), 
            5 => array(
                    '/technical contact\(s\):\n(?>[\x20\t]*)(.*?)$/is' => 'contacts:tech:address'), 
            6 => array('/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            7 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+)(.+)(?>[\x20\t]+).+$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+).+(?>[\x20\t]+)(.+)$/im' => 'ips'), 
            8 => array('/date registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/date of last change:(?>[\x20\t]*)(.+)$/im' => 'changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/is free/i';

    /**
     * After parsing ...
     * 
     * If dnssec key was found we set attribute to true. Furthermore
     * we are fixing the contact handle if the WHOIS contains one.
     * 
	 * @param  object &$WhoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec === 'yes') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                if (sizeof($filteredAddress) === 4) {
                    $contactObject->handle = $filteredAddress[0];
                    $contactObject->name = $filteredAddress[1];
                    $contactObject->phone = $filteredAddress[2];
                    $contactObject->email = $filteredAddress[3];
                    $contactObject->address = null;
                } else {
                    $contactObject->handle = $filteredAddress[0];
                    $contactObject->name = $filteredAddress[1];
                    $contactObject->address = $filteredAddress[2];
                    $contactObject->phone = $filteredAddress[3];
                    $contactObject->email = $filteredAddress[4];
                }
            }
        }
    }
}