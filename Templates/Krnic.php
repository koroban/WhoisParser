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
 * Template for KRNIC
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Krnic extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(\[ Network Information \])[\n]{1}(.*?)[\n]{2}/is', 
            2 => '/(\[ Admin Contact Information \])[\n]{1}(.*?)[\n]{2}/is', 
            3 => '/(\[ Tech Contact Information \])[\n]{1}(.*?)[\n]{2}/is', 
            4 => '/(\[ Network Abuse Contact Information \])[\n]{1}(.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^IPv4 Address[\s]*:[\s]*(.+)$/im' => 'network:inetnum', 
                    '/^IPv6 Address[\s]*:[\s]*(.+)$/im' => 'network:inetnum', 
                    '/^Service Name[\s]*:[\s]*(.+)$/im' => 'network:name', 
                    '/^Organization ID[\s]*:[\s]*(.+)$/im' => 'contacts:owner:handle', 
                    '/^Organization Name[\s]*:[\s]*(.+)$/im' => 'contacts:owner:name', 
                    '/^Address[\s]*:[\s]*(.+)$/im' => 'contacts:owner:address', 
                    '/^Zip Code[\s]*:[\s]*(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^Registration Date[\s]*:[\s]*(.+)$/im' => 'created'), 
            
            2 => array('/^Name[\s]*:[\s]*(.+)$/im' => 'contacts:admin:name', 
                    '/^Phone[\s]*:[\s]*(.+)$/im' => 'contacts:admin:phone', 
                    '/^E-Mail[\s]*:[\s]*(.+)$/im' => 'contacts:admin:email'), 
            
            3 => array('/^Name[\s]*:[\s]*(.+)$/im' => 'contacts:tech:name', 
                    '/^Phone[\s]*:[\s]*(.+)$/im' => 'contacts:tech:phone', 
                    '/^E-Mail[\s]*:[\s]*(.+)$/im' => 'contacts:tech:email'), 
            
            4 => array('/^Name[\s]*:[\s]*(.+)$/im' => 'contacts:abuse:name', 
                    '/^Phone[\s]*:[\s]*(.+)$/im' => 'contacts:abuse:phone', 
                    '/^E-Mail[\s]*:[\s]*(.+)$/im' => 'contacts:abuse:email'));
}