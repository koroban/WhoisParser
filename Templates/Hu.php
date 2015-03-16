<?php

namespace Novutec\WhoisParser\Templates;

class Hu extends Standard
{

    public function parse($result, $rawdata, $query)
    {
        $rawdata = utf8_encode($rawdata);
        parent::parse($result, $rawdata, $query);
    }


    protected function reformatData()
    {
        $dateFields = array('record created');
        foreach ($dateFields as $field) {
            if (array_key_exists($field, $this->data) && strlen($this->data[$field])) {
                $this->data[$field] = str_replace('.', '-', $this->data[$field]);
            }
        }
    }


    public function translateRawData($rawdata, $config)
    {
        return utf8_encode($rawdata);
    }
}
