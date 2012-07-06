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
 * Template for .PL
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Pl extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/domain name:(?>[\x20\t]*)(.*?)(?=technical contact:|registrar:)/is', 
            2 => '/technical contact:(?>[\x20\t]*)(.*?)(?=registrar:)/is', 
            3 => '/registrar:(?>[\x20\t]*)(.*?)(?=WHOIS displays data)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/nameservers:(?>[\x20\t]*)(.+)\n(?=created:)/is' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)\n/im' => 'created', 
                    '/^last modified:(?>[\x20\t]*)(.+)\n/im' => 'changed', 
                    '/^renewal date:(?>[\x20\t]*)(.+)\n/im' => 'expires', 
                    '/^dnssec:(?>[\x20\t]*)(.+)\n/im' => 'dnssec'), 
            
            2 => array('/company:(?>[\x20\t]*)(.+)\n(?=street:)/is' => 'contacts:tech:name', 
                    '/^street:(?>[\x20\t]*)(.+)\n/im' => 'contacts:tech:address', 
                    '/^city:(?>[\x20\t]*)(.+)\n/im' => 'contacts:tech:city', 
                    '/^location:(?>[\x20\t]*)(.+)\n/im' => 'contacts:tech:country', 
                    '/^handle:(?>[\x20\t]*)(.+)\n/im' => 'contacts:tech:handle', 
                    '/^phone:(?>[\x20\t]*)(.+)\n/im' => 'contacts:tech:phone', 
                    '/^fax:(?>[\x20\t]*)(.+)\n/im' => 'contacts:tech:fax', 
                    '/^last modified:(?>[\x20\t]*)(.+)\n/im' => 'contacts:tech:changed'), 
            
            3 => array('/registrar:\n(.*)\n\n/is' => 'registrar:name'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No information available about domain/i';

    /**
     * After parsing ...
     * 
     * Fix address, registrar handle and nameserver in whois output
     * 
     * @param  object $WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                if (! is_array($contactObject->name)) {
                    $explodedName = explode("\n", trim($contactObject->name));
                    
                    if (isset($explodedName[0])) {
                        $contactObject->name = trim($explodedName[0]);
                    }
                    if (isset($explodedName[1])) {
                        $contactObject->organization = trim($explodedName[1]);
                    }
                }
            }
        }
        
        if (! empty($ResultSet->registrar->name)) {
            $explodedName = explode("\n", trim($ResultSet->registrar->name));
            
            if (isset($explodedName[0])) {
                $ResultSet->registrar->name = trim($explodedName[0]);
            }
            if (isset($explodedName[4]) && sizeof($explodedName == 5)) {
                $ResultSet->registrar->email = str_replace('e-mail:', '', trim($explodedName[4]));
            }
            if (isset($explodedName[5]) && sizeof($explodedName == 6)) {
                $ResultSet->registrar->email = str_replace('e-mail:', '', trim($explodedName[5]));
            }
        }
        
        if (! empty($ResultSet->nameserver)) {
            $explodedNameserver = explode("\n", trim($ResultSet->nameserver));
            
            foreach ($explodedNameserver as $key => $nameserver) {
                $explodedNameserver[$key] = trim($nameserver);
            }
            
            $ResultSet->nameserver = $explodedNameserver;
        }
        
        if ($ResultSet->dnssec == 'Unsigned') {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
    }
}