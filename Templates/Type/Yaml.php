<?php

namespace Novutec\WhoisParser\Templates\Type;

use Novutec\WhoisParser\Exception\ReadErrorException;
use Novutec\WhoisParser\Result\Result;
use Symfony\Component\Yaml\Parser;

class Yaml extends KeyValue
{

    /**
     * @param \Novutec\WhoisParser\Result\Result $previousResult
     * @param $rawdata
     * @param string|object $query
     */
    public function parse($previousResult, $rawdata, $query)
    {
        $this->result = new Result();
        $parsedAvailable = $this->parseAvailable($rawdata, $this->result);

        $yaml = new Parser();
        $v = $yaml->parse($rawdata);
        $this->flattenYaml($v);

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


    protected function flattenYaml($yaml, $prefix = '')
    {
        if (!is_array($yaml)) {
            return;
        }

        $kPrefix = '';
        if (strlen($prefix)) {
            $kPrefix = $prefix . ':';
        }

        foreach ($yaml as $k => $v)
        {
            if (!is_array($v)) {
                $this->data[$kPrefix . $k] = $v;
                continue;
            }

            $this->flattenYaml($v, $kPrefix . $k);
        }
    }

}
