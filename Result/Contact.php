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
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser
 */
namespace Novutec\WhoisParser;

/**
 * WhoisParser Result Contact
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Contact extends AbstractResult
{

    /**
	 * Handle name
	 * 
	 * @var string
	 * @access protected
	 */
    protected $handle;

    /**
     * Handle type
     *
     * @var string
     * @access protected
     */
    protected $type;

    /**
	 * Name of person
	 * 
	 * @var string
	 * @access protected
	 */
    protected $name;

    /**
	 * Name of organization
	 * 
	 * @var string
	 * @access protected
	 */
    protected $organization;

    /**
	 * Email address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $email;

    /**
	 * Address field
	 * 
	 * @var array
	 * @access protected
	 */
    protected $address;

    /**
	 * Zipcode of address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $zipcode;

    /**
	 * City of address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $city;

    /**
	 * State of address
	 *
	 * @var string
	 * @access protected
	 */
    protected $state;

    /**
	 * Country of address
	 * 
	 * @var string
	 * @access protected
	 */
    protected $country;

    /**
	 * Phone number
	 * 
	 * @var string
	 * @access protected
	 */
    protected $phone;

    /**
	 * Fax number
	 * 
	 * @var string
	 * @access protected
	 */
    protected $fax;

    /**
	 * Created date of handle
	 * 
	 * @var string
	 * @access protected
	 */
    protected $created;

    /**
	 * Last changed date of handle
	 * 
	 * @var string
	 * @access protected
	 */
    protected $changed;

    /**
     * Convert properties to json
     *
     * @return string
     */
    public function toJson()
    {
        return json_encode($this->toArray());
    }

    /**
     * Convert properties to array
     *
     * @return array
     */
    public function toArray()
    {
        return get_object_vars($this);
    }
}