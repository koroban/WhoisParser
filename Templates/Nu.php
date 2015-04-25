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
 * @author     Hantrick <hantrick.se> - Based on template by estshy <estshy.pl>
 */

/**
 * @namespace Novutec\Whois\Parser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for .NU
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Nu extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
        1 => '/state(.*?)$/is',
    );

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                '/^nserver:(?>[\s]+)(.+)$/im'       => 'nameserver',
                '/^created:(?>[\x20\t]*)(.+)$/im'   => 'created',
                '/^modified:(?>[\x20\t]*)(.+)$/im'  => 'changed',
                '/^expires:(?>[\x20\t]*)(.+)$/im'   => 'expires',
                '/^registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name',
                '/^status:(?>[\x20\t]*)(.+)$/im' => 'status',
                '/^dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec',

                '/^holder:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle',
                '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle',
                '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle',
                '/^billing-c:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle',
            )
    );

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/" not found./i';

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
        if (preg_match("/unsigned/i", $ResultSet->dnssec)) {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
    }
}