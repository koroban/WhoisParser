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
 * Template for .AT
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_At extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*).*?[\n]{2}/is', 
            2 => '/personname:(?>[\x20\t]*).*?[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^remarks:(?>[\x20\t]*)(.+)$/im' => 'ips', 
                    '/^_mnt-by:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^registrant:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech'), 
            
            2 => array('/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^personname:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/^street address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/^city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/^country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed', 
                    '/^_status:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/^_mnt-by:(?>[\x20\t]*)(.+)$/im' => 'contacts:maintaner'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(% nothing found)[\r\n]/i';
}