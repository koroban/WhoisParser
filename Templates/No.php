<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Adapter\AbstractAdapter;
use Novutec\WhoisParser\Templates\Type\KeyValue;

class No extends KeyValue
{

    protected $regexKeys = array(
        'name' => '/^Domain Name$/i',
        'created' => '/^Domain Created$/i',
        'changed' => '/^Domain Last Updated$/i',
        // Registrar
        'registrar:id' => '/^Registrar Handle$/i',
        // Contacts: Owner
        'contacts:owner:handle' => '/^Domain Holder Handle$/i',
        'contacts:owner:type' => '/^Type$/i',
        'contacts:owner:name' => '/^Name$/i',
        'contacts:owner:address' => '/^Post Address$/i',
        'contacts:owner:city' => '/^Postal Area$/i',
        'contacts:owner:zipcode' => '/^Postal Code$/i',
        'contacts:owner:country' => '/^Country$/i',
        'contacts:owner:phone' => '/^Phone Number$/i',
        'contacts:owner:fax' => '/^Fax Number$/i',
        'contacts:owner:email' => '/^Email Address$/i',
        'contacts:owner:created' => '/^Holder Created$/i',
        'contacts:owner:changed' => '/^Holder Last Updated$/i',
        // Contacts: Admin
        'contacts:admin:handle' => '/^Legal-c Handle$/i',
        // Contacts: Tech
        'contacts:tech:handle' => '/^Tech-c Handle$/i',
    );

    protected $regexKeysNameservers = array(
        'nameserver' => '/^Name Server Hostname$/i',
    );

    protected $regexKeysContacts = array(
        ':type' => '/^Type$/',
        ':name' => '/^Name$/',
        ':address' => '/^Post Address$/i',
        ':city' => '/^Postal Area$/i',
        ':zipcode' => '/^Postal Code$/i',
        ':country' => '/^Country$/i',
        ':phone' => '/^Phone Number$/i',
        ':fax' => '/^Fax Number$/i',
        ':email' => '/^Email Address$/i',
        ':created' => '/^Created$/i',
        ':changed' => '/^Last Updated$/i',
    );

    protected $regexKeysRegistrar = array(
        'registrar:name' => '/^Registrar Name$/i',
        'registrar:address' => '/^Address$/i',
        'registrar:phone' => '/^Phone Number$/i',
        'registrar:fax' => '/^Fax Number$/i',
        'registrar:email' => '/^Email Address$/i',
    );


    protected $available = '/No match/i';


    protected function reformatData()
    {
        $this->data = $this->reformatDataArray($this->data);
    }


    protected function reformatDataArray($dataArray)
    {
        $firstValueKeys = array('NORID Handle', 'Created', 'Last updated');
        foreach ($dataArray as $key => $value) {
            unset($dataArray[$key]);
            $key = rtrim($key, '.');

            if (is_array($value)) {
                if (in_array($key, $firstValueKeys)) {
                    $dataArray['Domain ' . $key] = array_shift($value);
                    $dataArray['Holder ' . $key] = array_shift($value);
                    continue;
                }

                $value = array_unique($value);
                if (count($value) == 1) {
                    $value = array_shift($value);
                }
            }

            $dataArray[$key] = $value;
        }

        return $dataArray;
    }


    public function postProcess(&$whoisParser)
    {
        $whoisResult = $whoisParser->getResult();
        $configObj = $whoisParser->getConfig();
        $config = $configObj->getCurrent();
        $proxyConfig = $whoisParser->getProxyConfigFile();
        $customNamespace = $whoisParser->getCustomAdapterNamespace();
        $adapter = AbstractAdapter::factory('socket', $proxyConfig, $customNamespace);

        // Fetch nameservers
        foreach ($this->data['Name Server Handle'] as $nsHandle) {
            $config['format'] = $nsHandle;
            $result = $adapter->call($nsHandle, $config);
            $result = $this->translateRawData($result, $config);
            $whoisResult->addItem('rawdata', $result);

            if (! array_key_exists('Name Server Hostname', $this->data)) {
                $this->data['Name Server Hostname'] = array();
            }

            $data = $this->parseRawData($result);
            $data = $this->reformatDataArray($data);
            $this->parseKeyValues($whoisResult, $data, $this->regexKeysNameservers, true);
        }

        // Fetch additional contacts
        $contactKeys = array(
            'contacts:admin' => 'Legal-c Handle',
            'contacts:tech' => 'Tech-c Handle',
        );
        foreach ($contactKeys as $contactKey => $handleKey) {
            if (! array_key_exists($handleKey, $this->data)) {
                continue;
            }

            $config['format'] = $this->data[$handleKey];
            $result = $adapter->call($this->data[$handleKey], $config);
            $result = $this->translateRawData($result, $config);
            $whoisResult->addItem('rawdata', $result);

            $data = $this->parseRawData($result);
            $data = $this->reformatDataArray($data);
            $regexContacts = array();
            foreach ($this->regexKeysContacts as $key => $regex) {
                $regexContacts[$contactKey . $key] = $regex;
            }
            $this->parseKeyValues($whoisResult, $data, $regexContacts, true);
        }

        if (array_key_exists('Registrar Handle', $this->data)) {
            $registrarHandle = $this->data['Registrar Handle'];
            $config['format'] = $registrarHandle;
            $result = $adapter->call($registrarHandle, $config);
            $result = $this->translateRawData($result, $config);
            $whoisResult->addItem('rawdata', $result);

            $data = $this->parseRawData($result);
            $data = $this->reformatDataArray($data);
            $this->parseKeyValues($whoisResult, $data, $this->regexKeysRegistrar, true);
        }
    }
}
