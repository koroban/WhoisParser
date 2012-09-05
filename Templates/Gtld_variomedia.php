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
 * Template for Gtld_variomedia
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Template_Gtld_variomedia extends AbstractTemplate
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/\[Registrant\](.*?)(?=\[Admin\])/is', 
            2 => '/\[Admin\](.*?)(?=\[Tech\])/is', 
            3 => '/\[Tech\](.*?)(?=\[Nameservers\])/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^(First|Last) name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Street[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^State:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^Postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/^Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^(First|Last) name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Street[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^State:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^Postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'),  
            3 => array('/^Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^(First|Last) name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Street[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^State:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^Postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'));
}