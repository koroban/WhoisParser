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
 * Template for IANA #141
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_cronon extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/nameserver:(?>[\x20\t]*)(.*?)(?=Admin-C Name:)/is', 
            2 => '/Admin-C Name:(?>[\x20\t]*)(.*?)(?=Tech-C Name:)/is', 
            3 => '/Tech-C Name:(?>[\x20\t]*)(.*?)(?=Zone-C Name)/is', 
            4 => '/Zone-C Name:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/^nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            2 => array('/^Admin-C Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Admin-C Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^Admin-C Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Admin-C Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^Admin-C Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            3 => array('/^Tech-C Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Tech-C Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^Tech-C Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Tech-C Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^Tech-C Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/^Zone-C Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:name', 
                    '/^Zone-C Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:address', 
                    '/^Zone-C Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:phone', 
                    '/^Zone-C Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:fax', 
                    '/^Zone-C Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:email'));
}