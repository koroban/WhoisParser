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
 * Template for .PL
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
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
            1 => array('/^(nameservers:)?(?>[\x20\t]+)(.+)\./im' => 'nameserver', 
                    '/^(nameservers:)?(?>[\x20\t]+)(.+)\. \[.+\]/im' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/last modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/renewal date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            
            2 => array('/company:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(?>[\x20\t]+)(.+)$/im' => 'contacts:tech:organization', 
                    '/street:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/location:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/last modified:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:changed'), 
            
            3 => array('/registrar:\n(.*)$/im' => 'registrar:name', 
                    '/(?=fax:).+\n(.+)\n\n$/is' => 'registrar:email'));

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
     * If dnssec key was found we set attribute to true.
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec === 'Unsigned') {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
    }
}