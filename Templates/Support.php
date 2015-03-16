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
 * Template for IANA #146, #440
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Support extends Regex
{

    /**
     * Blocks within the raw output of the whois
     * 
     * @var array
     * @access protected
     */
    protected $blocks = array(
        1 => '/Domain Name:(.*?)(?=Registrant ID)/is'
    );

    /**
     * Items for each block
     * 
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array('/Registry Expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires')
    );
}