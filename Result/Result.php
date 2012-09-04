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
 * @see Result/AbstractResult
 */
require_once WHOISPARSERPATH . '/Result/AbstractResult.php';

/**
 * @see Result/Conact
 */
require_once WHOISPARSERPATH . '/Result/Contact.php';

/**
 * @see Result/Registrar
 */
require_once WHOISPARSERPATH . '/Result/Registrar.php';

/**
 * WhoisParser Result
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2012 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Result extends AbstractResult
{

    /**
     * Name of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $name;

    /**
     * IDN converted name of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $idnName;

    /**
     * Status of domain or IP address
     *
     * @var array
     * @access protected
     */
    protected $status;

    /**
     * Array of Nameservers
     *
     * @var array
     * @access protected
     */
    protected $nameserver;

    /**
     * Array of Nameservers IPs
     *
     * @var array
     * @access protected
     */
    protected $ips;

    /**
     * Created date of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $created;

    /**
     * Last changed date of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $changed;

    /**
     * Expire date of domain or IP address
     *
     * @var string
     * @access protected
     */
    protected $expires;

    /**
     * Is domain name or IP address registered
     *
     * @var boolean
     * @access protected
     */
    protected $registered;

    /**
     * Has domain name DNSSEC
     *
     * @var boolean
     * @access protected
     */
    protected $dnssec;

    /**
     * Queried whois server
     *
     * @var string
     * @access protected
     */
    protected $whoisserver;

    /**
     * Contact handles of domain name or IP address
     *
     * @var object
     * @access protected
     */
    protected $contacts;

    /**
     * Registrar of domain name or IP address
     *
     * @var object
     * @access protected
     */
    protected $registrar;

    /**
     * Raw response from whois server
     *
     * @var array
     * @access protected
     */
    protected $rawdata;

    /**
     * Network information of domain name or IP address
     *
     * @var object
     * @access protected
     */
    protected $network;

    /**
     * Exception
     *
     * @var string
     * @access protected
     */
    protected $exception;

    /**
     * Have contacts been parsed?
     * 
     * @var boolean
     * @access protected
     */
    protected $parsedContacts;

    /**
	 * Creates a WhoisParserResult object
	 *
	 * @return void
	 */
    public function __construct()
    {
        $this->contacts = new \stdClass();
        $this->lastId = - 1;
    }

    /**
     * @param  string $target
     * @param  mixed $value
     * @return void
     */
    public function addItem($target, $value)
    {
        if (is_array($value) && sizeof($value) == 1) {
            $value = $value[0];
        }
        
        // reservedType is sometimes need by templates like .DE
        if ($target == 'contacts:reservedType') {
            if ($this->lastHandle != strtolower($value)) {
                $this->lastId = - 1;
            }
            
            $this->lastHandle = strtolower($value);
            $this->lastId++;
            return;
        }
        
        if (strpos($target, ':')) {
            // split target by :
            $targetArray = explode(':', $target);
            $element = &$this;
            
            // lookup target to determine where we should add the item
            foreach ($targetArray as $key => $type) {
                if ($targetArray[0] == 'contacts' && $key == 1 && sizeof($targetArray) == 2) {
                    // estimate handle match by network contacts
                    if (isset($this->network->contacts) && $targetArray[1] == 'handle') {
                        // look through all network contacts
                        foreach ($this->network->contacts as $networkContactKey => $networkContactValue) {
                            // if it is an array, then there are more contacts
                            // of the same type
                            if (is_array($networkContactValue)) {
                                // look through the array of one type
                                foreach ($networkContactValue as $multiContactKey => $multiContactValue) {
                                    if (strtolower($multiContactValue) == strtolower($value)) {
                                        if ($this->lastHandle != $networkContactKey) {
                                            $this->lastId = - 1;
                                        }
                                        
                                        $this->lastHandle = $networkContactKey;
                                        $this->lastId++;
                                        unset($this->network->contacts->{$networkContactKey}[$multiContactKey]);
                                        break 2;
                                    }
                                }
                            } else {
                                if (strtolower($networkContactValue) == strtolower($value)) {
                                    if ($this->lastHandle != $networkContactKey) {
                                        $this->lastId = - 1;
                                    }
                                    $this->lastHandle = $networkContactKey;
                                    $this->lastId++;
                                    unset($this->network->contacts->$networkContactKey);
                                    break;
                                }
                            }
                        }
                    }
                    
                    if (! isset($this->contacts->{$this->lastHandle}[$this->lastId])) {
                        $this->contacts->{$this->lastHandle}[$this->lastId] = new \Novutec\WhoisParser\Contact();
                    }
                    
                    $this->contacts->{$this->lastHandle}[$this->lastId]->$type = $value;
                } else {
                    // if last element of target is reached we need to add value
                    if ($key == sizeof($targetArray) - 1) {
                        if (is_array($element)) {
                            $element[sizeof($element) - 1]->$type = $value;
                        } else {
                            $element->$type = $value;
                        }
                        break;
                    }
                    
                    if (! isset($element->$type)) {
                        switch ($targetArray[0]) {
                            case 'contacts':
                                if (empty($element->$type)) {
                                    $element->$type = array();
                                }
                                
                                array_push($element->$type, new \Novutec\WhoisParser\Contact());
                                break;
                            case 'registrar':
                                $element->$type = new \Novutec\WhoisParser\Registrar();
                                break;
                            default:
                                $element->$type = new \stdClass();
                        }
                    }
                    
                    $element = &$element->$type;
                }
            }
        } else {
            $this->{$target} = $value;
        }
    }

    /**
     * Resets the result properties to empty
     *  
     * @return void
     */
    public function reset()
    {
        foreach ($this as $key => $value) {
            $this->$key = null;
        }
        
        // need to set contacts to stdClass otherwise it will not working to
        // add items again
        $this->contacts = new \stdClass();
        $this->lastId = - 1;
    }

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
        $output = get_object_vars($this);
        $contacts = array();
        $network = array();
        
        // lookup all contact handles and convert to array
        foreach ($this->contacts as $type => $handle) {
            foreach ($handle as $number => $object) {
                $contacts[$type][$number] = $object->toArray();
            }
        }
        $output['contacts'] = $contacts;
        
        if (! empty($this->registrar)) {
            $output['registrar'] = $this->registrar->toArray();
        }
        
        if (! empty($this->network)) {
            // lookup network for all properties
            foreach ($this->network as $type => $value) {
                // if there is an object we need to convert it to array
                if (is_object($value)) {
                    $value = (array) $value;
                    // if converted array is empty there is no need to add it
                    if (! empty($value)) {
                        $network[$type] = $value;
                    }
                } else {
                    $network[$type] = $value;
                }
            }
            $output['network'] = $network;
        }
        
        return $output;
    }

    /**
     * Serialize properties
     *
     * @return string
     */
    public function serialize()
    {
        return serialize($this->toArray());
    }

    /**
     * Convert properties to xml by using SimpleXMLElement
     *
     * @return string
     */
    public function toXml()
    {
        $xml = new \SimpleXMLElement(
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><whois></whois>');
        
        $output = get_object_vars($this);
        
        // lookup all object variables
        foreach ($output as $name => $var) {
            // if variable is an array add it to xml
            if (is_array($var)) {
                $child = $xml->addChild($name);
                
                foreach ($var as $firstKey => $firstValue) {
                    $child->addChild('item', trim(htmlspecialchars($firstValue)));
                }
            } elseif (is_object($var)) {
                // if variable is an object we need to convert it to array
                $child = $xml->addChild($name);
                
                // if it is not a stdClass object we have the toArray() method
                if (! $var instanceof \stdClass) {
                    $firstArray = $var->toArray();
                    
                    foreach ($firstArray as $firstKey => $firstValue) {
                        if (! is_array($firstValue)) {
                            $child->addChild($firstKey, trim(htmlspecialchars($firstValue)));
                        } else {
                            $secondChild = $child->addChild($firstKey);
                            
                            foreach ($firstValue as $secondKey => $secondString) {
                                $secondChild->addChild('item', trim(htmlspecialchars($secondString)));
                            }
                        }
                    }
                } else {
                    // if it is an stdClass object we need to convert it
                    // manually
                    
                    // lookup all properties of stdClass and convert it
                    foreach ($var as $firstKey => $firstValue) {
                        if (! $firstValue instanceof \stdClass && ! is_array($firstValue) &&
                                 ! is_string($firstValue)) {
                            $secondChild = $child->addChild($firstKey);
                            
                            $firstArray = $firstValue->toArray();
                            
                            foreach ($firstArray as $secondKey => $secondValue) {
                                $secondChild->addChild($secondKey, trim(htmlspecialchars($secondValue)));
                            }
                        } elseif (is_array($firstValue)) {
                            $secondChild = $child->addChild($firstKey);
                            
                            foreach ($firstValue as $secondKey => $secondValue) {
                                $secondArray = $secondValue->toArray();
                                $thirdChild = $secondChild->addChild('item');
                                
                                foreach ($secondArray as $thirdKey => $thirdValue) {
                                    if (! is_array($thirdValue)) {
                                        $thirdChild->addChild($thirdKey, trim(htmlspecialchars($thirdValue)));
                                    } else {
                                        $fourthChild = $thirdChild->addChild($thirdKey);
                                        
                                        foreach ($thirdValue as $fourthKey => $fourthValue) {
                                            $fourthChild->addChild('item', trim(htmlspecialchars($fourthValue)));
                                        }
                                    }
                                }
                            }
                        } elseif (is_string($firstValue)) {
                            $secondChild = $child->addChild($firstKey, $firstValue);
                        }
                    }
                }
            } else {
                $xml->addChild($name, trim($var));
            }
        }
        
        return $xml->asXML();
    }
}