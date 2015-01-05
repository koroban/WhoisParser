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
    protected $blocks = array(
        1 => '/domain:(?>[\x20\t]*)(.*?)(?=\% registrar)/is',
        2 => '/\% registrant:(.*?)\% administrative contacts:/is',
        3 => '/\% (administrative|technical) contacts:(.*?)(?=(\% (administrative|technical) contacts:|\% query time))/is',
    );

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array(
            '/status:(?>[\x20\t]*)(.+)$/im' => 'status',
            '/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver',
            '/registrant:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner',
            '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin',
            '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech',
            '/created:(?>[\x20\t]*)(.+)$/im' => 'created',
            '/modified:(?>[\x20\t]*)(.+)$/im' => 'changed',
            '/expires:(?>[\x20\t]*)(.+)$/im' => 'expires',
        ),
        2 => array(
            '/contact-id:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle',
            '/person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name',
            '/organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization',
            '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address',
            '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone',
            '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax',
            '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email',
            '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country',
            '/postal-code:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode',
        ),
        3 => array(
            '/contact-id:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle',
            '/person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name',
            '/organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization',
            '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address',
            '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone',
            '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax',
            '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email',
            '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country',
            '/postal-code:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode',
        ),
    );

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

        $dateFields = array('created', 'changed', 'expires');
        foreach ($dateFields as $field) {
            if (isset($ResultSet->{$field}) && strlen($ResultSet->{$field})) {
                $dateV = $ResultSet->{$field};
                if (substr($dateV, -3, 1) != '+') {
                    continue;
                }
                $dateV .= '00';
                $date = \DateTime::createFromFormat('Y-m-d H:i:sO', $dateV);
                $date->setTimezone(new \DateTimeZone(date_default_timezone_get()));
                if (is_object($date)) {
                    $ResultSet->{$field} = $date->format('Y-m-d H:i:s');
                }
            }
        }
    }
}
