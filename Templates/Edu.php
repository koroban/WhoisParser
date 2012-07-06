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
 * Template for .EDU
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Edu extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain record activated:(.*?)$/is', 
            2 => '/Registrant:(.*?)(?=Administrative Contact\:)/is', 
            3 => '/Administrative Contact:(.*?)(?=Technical Contact\:)}/is', 
            4 => '/Technical Contact:(.*?)(?=Name Servers\:)/is', 
            5 => '/Name Servers:(.*?)(?=Domain record activated\:)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Domain record activated:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Domain record last updated:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Domain expires:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            
            2 => array('/^(?>[\x20\t]*)name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^(?>[\x20\t]*)website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'), 
            
            3 => array('/^(?>[\x20\t]+)keyTag:(.+)$/im' => 'dnssec'), 
            
            4 => array('/^(?>[\x20\t]+)keyTag:(.+)$/im' => 'dnssec'), 
            
            5 => array('/^(?>[\x20\t]+)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Match/i';
}