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
 * Template for .SG
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Sg extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(?>[\x20\t]*)Registrar:(?>[\x20\t]*)(.*?)(?=Registrant)/is', 
            2 => '/(?>[\x20\t]*)Registrant:(?>[\x20\t]*)(.*?)(?=Administrative Contact)/is', 
            3 => '/(?>[\x20\t]*)Administrative Contact:(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            4 => '/(?>[\x20\t]*)Technical Contact:(?>[\x20\t]*)(.*?)(?=Name Servers)/is', 
            5 => '/(?>[\x20\t]*)Name Servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^(?>[\x20\t]*)Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^(?>[\x20\t]*)Creation Date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^(?>[\x20\t]*)Modified Date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^(?>[\x20\t]*)Expiration Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^(?>[\x20\t]*)Domain Status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            
            2 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:owner:name', 
                    '/(?>[\x20\t]*)Name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:owner:handle'), 
            
            3 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:admin:name', 
                    '/(?>[\x20\t]*)Name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:admin:handle'), 
            
            4 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:tech:name', 
                    '/(?>[\x20\t]*)Name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:tech:handle', 
                    '/(?>[\x20\t]*)Email:(?>[\x20\t]*)(.+)/im' => 'contacts:tech:email'), 
            
            5 => array('/Name Servers:[\r\n](?>[\x20\t]*)(.*)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain Not Found/i';

    /**
     * After parsing ...
     *
     * Fix nameserver in whois output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        
        if (isset($ResultSet->nameserver) && $ResultSet->nameserver != '' &&
                 ! is_array($ResultSet->nameserver)) {
            $explodedNameserver = explode("\n", $ResultSet->nameserver);
            foreach ($explodedNameserver as $key => $line) {
                if (trim($line) != '') {
                    $filteredNameserver[] = strtolower(trim($line));
                }
            }
            $ResultSet->nameserver = $filteredNameserver;
        }
    }
}