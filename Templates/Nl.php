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
 * Template for .FR
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
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
    protected $blocks = array(1 => '/(domain name):[\s]*(.*?)[\n]{2}/is', 
            2 => '/(registrar):[\n](.*?)[\n]{2}/is', 
            3 => '/(domain nameservers):[\n](.*?)[\n]{2}/is', 4 => '/(dnssec):[\s]*(.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:[\s]*(.+)$/im' => 'status', '/^created:[\s]*(.+)$/im' => 'created'), 
            
            2 => array('/^([\s]+)(.+)$/im' => 'registrar'), 
            
            3 => array('/^([\s]+)(.+)$/im' => 'nameserver'), 
            
            4 => array('/^dnssec:[\s]*(.+)$/im' => 'dnssec'));

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
	 * @param  object &$whoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != 'no') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}