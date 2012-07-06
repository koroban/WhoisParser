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
 * Template for .EU
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Eu extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/registrar technical contacts:[\r\n](.*?)[\n]{2}/is', 
            2 => '/registrar:[\r\n](.*?)[\n]{2}/is', 3 => '/name servers:[\r\n](.*?)[\n]{2}/is', 
            4 => '/keys:[\r\n](.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^(?>[\x20\t]*)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(?>[\x20\t]*)organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^(?>[\x20\t]*)language:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:language', 
                    '/^(?>[\x20\t]*)phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^(?>[\x20\t]*)fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^(?>[\x20\t]*)email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            
            2 => array('/^(?>[\x20\t]*)name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^(?>[\x20\t]*)website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'), 
            
            3 => array('/^(?>[\x20\t]+)(.+)$/im' => 'nameserver'), 
            
            4 => array('/^(?>[\x20\t]+)keyTag:(.+)$/im' => 'dnssec'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(Status:[\s]*AVAILABLE)[\r\n]/i';

    /**
     * After parsing ...
     * 
     * If dnssec was matched before it we switch dnssec to true otherwise to false
     * 
	 * @param  object $whoisParser
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