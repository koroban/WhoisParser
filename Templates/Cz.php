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
 * Template for .CZ
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Cz extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            2 => '/contact:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            3 => '/nserver:(?>[\x20\t]*)(.*?)[\n](?=tech-c:|registrar:|created:)/is', 
            4 => '/keyset:(?>[\x20\t]*)(.*?)[\n](?=tech-c:|registrar:|created:)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^registrant:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^expired:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/^contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^org:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/^name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'contacts:created', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'), 
            3 => array('/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            4 => array('/^ds:(?>[\x20\t]*)(.+)$/im' => 'dnssec'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/no entries found/i';

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