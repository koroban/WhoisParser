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
 * Template for .ST
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_St extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Administrative Contact)/is', 
            2 => '/Administrative Contact:(?>[\x20\t]*)(.*?)(?=Name Servers)/is', 
            3 => '/Name Servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrar:(?>[\x20\t]*)(.*?)$/im' => 'registrar:name', 
                    '/Creation Date:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/Updated Date:(?>[\x20\t]*)(.*?)$/im' => 'changed', 
                    '/Contact:(?>[\x20\t]*)(.*?)$/im' => 'registrar:email'), 
            2 => array('/Owner:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:organization', 
                    '/^(?>[\x20\t]*)Contact:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:name', 
                    '/Address:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:address', 
                    '/City:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:city', 
                    '/Country:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:country'), 
            3 => array('/Name Servers:[\r\n]{1,2}(?>[\x20\t]*)(.*?)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found/i';

    /**
     * After parsing do something
     *
     * Fix nameservers
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