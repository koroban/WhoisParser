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
 * @namespace Novutec\Whois\Parser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for .UA
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Ua extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=\% administrative contact)/is', 
            2 => '/\% (administrative|technical) contact:(.*?)(?=(\% technical contact:|\% \% .ua whois))/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/status:(?>[\x20\t]*).+ (.+)$/im' => 'expires', 
                    '/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/created:(?>[\x20\t]*).+ (.+)$/im' => 'created', 
                    '/changed:(?>[\x20\t]*).+ (.+)$/im' => 'changed'),
            2 => array('/nic-handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/changed:(?>[\x20\t]*).+ (.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found for/i';

    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $date = \DateTime::createFromFormat('YmdHis', $ResultSet->expires);

        $ResultSet->expires = '';
        if ($date instanceof \DateTime) {
            $ResultSet->expires = $date->format('Y-m-d H:i:s');
        }
    }
}