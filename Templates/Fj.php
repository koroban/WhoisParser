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
 * Template for .FJ
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Fj extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Status:(?>[\x20\t]*)(.*?)(?=Registrant)/is', 
            2 => '/Registrant:\n(?>[\x20\t]*)(.*?)(?=Domain servers)/is', 
            3 => '/Domain servers:\n(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Status:(?>[\x20\t]*)(.+)/im' => 'status', 
                    '/Expires:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/Registrant:\n(?>[\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array('/\n(?>[\x20\t]+)(.+) .+$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+).+ (.+)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/was not found/i';

    /**
     * After parsing do something
     *
     * Fix address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->owner[0]->address)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->owner[0]->address)));
            
            $ResultSet->contacts->owner[0]->name = $filteredAddress[0];
            $ResultSet->contacts->owner[0]->address = $filteredAddress[1];
        }
    }
}