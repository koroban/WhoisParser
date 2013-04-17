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
 * Template for .TW
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Tw extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/registrant:(?>[\x20\t]*)(.*?)(?=(administrative )?contact:)/is', 
            2 => '/(administrative )?contact:(?>[\x20\t]*)(.*?)(?=technical contact|record expires on)/is', 
            3 => '/technical contact:(?>[\x20\t]*)(.*?)(?=record expires on)/is', 
            4 => '/record expires on(?>[\x20\t]*)(.*?)(?=domain servers in listed)/is', 
            5 => '/domain servers in listed(?>[\x20\t]*)(.*?)(?=registration service provider)/is', 
            6 => '/registration service provider(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/registrant:\n(.*?)$/is' => 'contacts:owner:address'), 
            2 => array(
                    '/(administrative )?contact:\n(?>[\x20\t]*)(.*?)$/is' => 'contacts:admin:address'), 
            3 => array('/technical contact:\n(.*?)$/is' => 'contacts:tech:address'), 
            4 => array('/record expires on(?>[\x20\t]*)(.+) \(YYYY\-MM\-DD\)$/im' => 'expires', 
                    '/record created on(?>[\x20\t]*)(.+) \(YYYY\-MM\-DD\)$/im' => 'created'), 
            5 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver'), 
            6 => array('/registration service provider:(?>[\x20\t]*)(.+)$/im' => 'registrar:name'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Found/i';

    /**
     * After parsing do something
     *
     * Fix contact addresses
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                switch ($contactType) {
                    case 'owner':
                        if (sizeof($filteredAddress) === 7) {
                            $contactObject->organization = $filteredAddress[0];
                            $contactObject->phone = $filteredAddress[2];
                            $contactObject->fax = $filteredAddress[3];
                            $contactObject->city = $filteredAddress[5];
                            $contactObject->country = $filteredAddress[6];
                            
                            preg_match('/^(.*) ([a-z0-9\-\.@_]*)$/im', $filteredAddress[1], $matches);
                            $contactObject->name = $matches[1];
                            $contactObject->email = $matches[2];
                            
                            $contactObject->address = $filteredAddress[4];
                        }
                        
                        if (sizeof($filteredAddress) === 3) {
                            $contactObject->organization = $filteredAddress[1];
                            $contactObject->address = array_map('trim', explode(',', trim($filteredAddress[2])));
                        }
                        break;
                    case 'admin':
                    case 'tech':
                        preg_match('/^(.*) ([a-z0-9\-\.@_]*)$/im', $filteredAddress[0], $matches);
                        
                        if (empty($matches)) {
                            $contactObject->name = $filteredAddress[0];
                        }
                        
                        if (isset($matches[1])) {
                            $contactObject->name = $matches[1];
                        }
                        
                        if (isset($matches[2])) {
                            $contactObject->email = $matches[2];
                            
                            if (isset($filteredAddress[1])) {
                                $contactObject->phone = trim(str_replace('TEL:', '', $filteredAddress[1]));
                            }
                            
                            if (isset($filteredAddress[2])) {
                                $contactObject->fax = trim(str_replace('FAX:', '', $filteredAddress[2]));
                            }
                        } else {
                            $contactObject->email = $filteredAddress[1];
                        }
                        
                        $contactObject->address = null;
                        break;
                }
            }
        }
    }
}