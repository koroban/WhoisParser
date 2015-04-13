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
 * @namespace Novutec\WhoisParser\Templates
 */
namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

/**
 * Template for IANA #83
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Gtld_schlund extends Regex
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array(
        0 => '/domain name:(?>[\x20\t]*)(.*?)(?=>>>)/is'
    );

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        0 => array(
            '/^registrant organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization',
            '/^registrant name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name',
            '/^registrant street[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address',
            '/^registrant city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city',
            '/^registrant state:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state',
            '/^registrant pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode',
            '/^registrant ccode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country',
            '/^registrant phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone',
            '/^registrant fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax',
            '/^registrant email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email',
            '/^tech organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization',
            '/^tech (first|last)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name',
            '/^tech street[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address',
            '/^tech city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city',
            '/^tech state:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state',
            '/^tech pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode',
            '/^tech ccode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country',
            '/^tech phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone',
            '/^tech fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax',
            '/^tech email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email',
            '/^admin organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization',
            '/^admin (first|last)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name',
            '/^admin street[0-9]*:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address',
            '/^admin city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city',
            '/^admin state:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state',
            '/^admin pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode',
            '/^admin ccode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country',
            '/^admin phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone',
            '/^admin fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax',
            '/^admin email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email',
            '/^created:(?>[\x20\t]*)(.+)$/im' => 'created',
            '/^updated date:(?>[\x20\t]*)(.+)$/im' => 'changed',
            '/^registration-expiration:(?>[\x20\t]*)(.+)$/im' => 'expires',
            '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'
        )
    );
}
