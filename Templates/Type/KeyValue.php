<?php

namespace Novutec\WhoisParser\Templates\Type;

use Novutec\WhoisParser\Exception\ReadErrorException;
use Novutec\WhoisParser\Result\Result;

/**
 * Parser based on simple responses containing only 'key: value' entries.
 * An alternative to the default regex-blocks based parser that allows us to not care about missing entries
 * or the order of entries
 *
 * @package Novutec\WhoisParser\Templates\Type
 */
abstract class KeyValue extends AbstractTemplate
{

    protected $data = array();

    protected $regexKeys = array();

    protected $result = null;

    protected $availabilityField = null;

    protected $availabilityValues = null;

    protected $kvSeparator = ':';


    /**
     * @param \Novutec\WhoisParser\Result\Result $previousResult
     * @param $rawdata
     * @param string|object $query
     * @throws \Novutec\WhoisParser\Exception\ReadErrorException if data was read from the whois response
     */
    public function parse($previousResult, $rawdata, $query)
    {
        $this->result = new Result();
        $this->parseRateLimit($rawdata);

        $parsedAvailable = $this->parseAvailable($rawdata, $this->result);

        $this->data = $this->parseRawData($rawdata);
        $this->reformatData();
        $parseMatches = $this->parseKeyValues($this->result, $this->data, $this->regexKeys, true);

        if (strlen($this->availabilityField)) {
            $availabilityValue = null;
            if (isset($this->result->{$this->availabilityField})) {
                $availabilityValue = $this->result->{$this->availabilityField};
            }

            if ($availabilityValue !== null) {
                $status = null;
                if (is_array($availabilityValue) && (count($availabilityValue) == 1)) {
                    // Copy the array first so we don't affect the result
                    $statusArr = $availabilityValue;
                    $status = array_shift($statusArr);
                } else if ((!is_array($availabilityValue)) && (strlen($availabilityValue) > 1)) {
                    $status = $availabilityValue;
                }
                if (strlen($status)) {
                    $status = strtolower($status);
                    $isRegistered = null;
                    if (in_array($status, $this->availabilityValues)) {
                        $isRegistered = false;
                    }

                    if ($isRegistered !== null) {
                        $parsedAvailable = true;
                        $this->result->addItem('registered', $isRegistered);
                    }
                }
            }
        }

        if (($parseMatches < 1) && (!$parsedAvailable)) {
            throw new ReadErrorException("Template ". get_class($this) ." did not correctly parse the response");
        }

        $previousResult->mergeFrom($this->result);
    }


    protected function parseRawData($rawdata)
    {
        $data = array();
        $rawdata = explode("\n", $rawdata);
        foreach ($rawdata as $line) {
            $line = trim($line);
            $lineParts = explode($this->kvSeparator, $line, 2);
            if (count($lineParts) < 2) {
                continue;
            }

            $key = trim($lineParts[0]);
            $value = trim($lineParts[1]);
            if (strlen($value) < 1) {
                continue;
            }

            if (array_key_exists($key, $data)) {
                if (! is_array($data[$key])) {
                    $data[$key] = array($data[$key]);
                }
                $data[$key][] = $value;
                continue;
            }

            $data[$key] = $value;
        }

        return $data;
    }


    protected function parseKeyValues($result, $dataArray, $regexKeys, $append = false)
    {
        $matches = 0;
        foreach ($dataArray as $key => $value) {
            foreach ($regexKeys as $dataKey => $regexList) {
                if (! is_array($regexList)) {
                    $regexList = array($regexList);
                }

                foreach ($regexList as $regex) {
                    if (preg_match($regex, $key)) {
                        $matches++;
                        $result->addItem($dataKey, $value, $append);
                        break 2;
                    }
                }
            }
        }

        return $matches;
    }


    /**
     * Perform any necessary reformatting of data (for example, reformatting dates)
     */
    protected function reformatData()
    {
    }
}
