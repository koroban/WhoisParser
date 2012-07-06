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
 * Template for APNIC
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Apnic extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/(inetnum|inet6num):(?>[\x20\t]*)(.*?)source:(?>[\x20\t]*)apnic/is', 
            2 => '/(role|person|organisation):(?>[\x20\t]*)(.*?)source:(?>[\x20\t]*)apnic/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^inetnum:(?>[\x20\t]*)(.+)$/im' => 'network:inetnum', 
                    '/^inet6num:(?>[\x20\t]*)(.+)$/im' => 'network:inetnum', 
                    '/^netname:(?>[\x20\t]*)(.+)$/im' => 'network:name', 
                    '/^mnt-by:(?>[\x20\t]*)(.+)$/im' => 'network:maintainer', 
                    '/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^source:(?>[\x20\t]*)(.+)$/im' => 'network:source'), 
            
            2 => array('/^organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^org:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^org-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^role:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^address:(?>[\x20\t]*)(.+)/im' => 'contacts:address', 
                    '/^abuse-mailbox:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax'));

    /**
     * After parsing do something
     * 
     * If APNIC says the organization is KRNIC then connect to KRNIC and
     * start over again.
     * 
	 * @param  object $whoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        
        if (isset($ResultSet->network->name) && $ResultSet->network->name == 'KRNIC-KR') {
            $ResultSet->reset();
            $Config->setCurrent($Config->get('krnic'));
            $WhoisParser->call();
        }
    }
}