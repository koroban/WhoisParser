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
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * @namespace Novutec\WhoisParser\Result
*/
namespace Novutec\WhoisParser\Result;

/**
 * WhoisParser AbstractResult
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
abstract class AbstractResult
{

    /**
     * Writing data to properties
     *
     * @param  string $name
     * @param  mixed $value
     * @return void
     */
    public function __set($name, $value)
    {
        $this->{$name} = $value;
    }

    /**
     * Checking data
     *
     * @param  mixed $name
     * @return boolean
     */
    public function __isset($name)
    {
        return isset($this->{$name});
    }

    /**
     * Reading data from properties
     *
     * @param  string $name
     * @return mixed
     */
    public function __get($name)
    {
        if (isset($this->{$name})) {
            return $this->{$name};
        }
        
        return null;
    }


    public function addItem($key, $value, $append = false)
    {
        if ($value === null) {
            $this->$key = null;
            return;
        }
        if (is_string($value) && (strlen($value) < 1)) {
            return;
        }
        if (is_array($value) && (count($value) < 1)) {
            return;
        }

        if (! (isset($this->$key) && ($key !== null))) {
            $this->$key = $value;
            return;
        }

        if ($append) {
            if ($this->$key !== null) {
                if (!is_array($this->$key)) {
                    $this->$key = array($this->$key);
                }
                $this->{$key}[] = $value;
                return;
            }
        }

        $this->$key = $value;
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
        return get_object_vars($this);
    }
}
