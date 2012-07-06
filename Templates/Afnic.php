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
 * Template for Afnic (.FR, .RE, .WF, .PM, .TF, .YT)
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Afnic extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:[\s]*(.*?)[\r\n]{2}/is', 
            2 => '/ns-list:[\s]*(.*?)[\r\n]{2}/is', 3 => '/nic-hdl:[\s]*(.*?)[\r\n]{2}/is', 
            4 => '/ds-list:[\s]*(.*?)[\r\n]{2}/is', 5 => '/registrar:[\s]*(.*?)[\r\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^last-update:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^hold:(?>[\x20\t]*)(.+)$/im' => 'hold', 
                    '/^holder-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^zone-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:zone'), 
            
            2 => array('/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            
            3 => array('/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^type:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/^contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'), 
            
            4 => array('/^key1-tag:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            
            5 => array('/^registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'registrar:email', 
                    '/^website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(%% No entries found in the AFNIC Database.)[\r\n]/i';

    /**
     * After parsing ...
     * 
     * If dnssec was matched before it we switch dnssec to true otherwise to false
     * 
	 * @param  object &$whoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}