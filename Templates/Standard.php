<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\KeyValue;

/**
 * A 'standard' template that will parse most key: value reponses
 *
 * @package Novutec\WhoisParser\Templates
 */
class Standard extends KeyValue
{

    protected $regexKeys = array(
        'name' => '/^Domain Name$/i',
        'ask_whois' => '/^Whois Server$/i',
        'created' => '/^(Domain |Record )?Creat(e|ed|ion)( On| Date)?$/i',
        'expires' => '/^(Domain )?(Registration )?(Expiration|Expires|Expiry) (On|Date)$/i',
        'changed' => '/^(Domain )?(Last )?Updated (On|Date)$/i',
        'nameserver' => '/^(Name Server|Name Server Name|Nameservers)$/i',
        'dnssec' => '/^DNSSEC/i',
        'status' => '/^(Domain )?Status$/i',
        // Registrar
        'registrar:id' => '/^Registrar IANA ID$/i',
        'registrar:email' => '/^Registrar Abuse Contact Email$/i',
        'registrar:name' => '/^Registrar$/i',
        'registrar:phone' => '/^Registrar Abuse Contact Phone$/i',
        'registrar:url' => '/^Referral URL$/i',
        // Contacts: Owner
        'contacts:owner:handle' => '/^(Registry Registrant|Owner)(\-| )ID$/i',
        'contacts:owner:name' => '/^(Registrant|Owner)(\-| )(Contact Name|Name)$/i',
        'contacts:owner:organization' => '/^(Registrant|Owner)( Organization)?$/i',
        'contacts:owner:address' => '/^(Registrant|Owner)(\-| )(Street|Address)[0-9]*$/i',
        'contacts:owner:city' => '/^(Registrant|Owner)(\-| )City$/i',
        'contacts:owner:state' => '/^(Registrant|Owner)(\-| )State(\/Province)?$/i',
        'contacts:owner:zipcode' => array(
            '/^(Registrant|Owner)(\-| )Postal(\-| )Code$/i',
            '/^(Registrant|Owner)(\-| )ZIP$/i'
        ),
        'contacts:owner:country' => '/^(Registrant|Owner)(\-| )Country(\/Economy)*$/i',
        'contacts:owner:phone' => '/^(Registrant|Owner)(\-| )Phone$/i',
        'contacts:owner:fax' => '/^(Registrant|Owner)(\-| )FAX$/i',
        'contacts:owner:email' => '/^(Registrant|Owner)(\-| )(Contact )?(Email|E-Mail)$/i',
        // Contacts: Admin
        'contacts:admin:handle' => '/^Admin(istrative)?(\-| )(Contact )?ID$/i',
        'contacts:admin:name' => '/^Admin(istrative)?(\-| )(Contact )?Name$/i',
        'contacts:admin:organization' => '/^Admin(istrative)?(\-| )(Contact )?Organization$/i',
        'contacts:admin:address' => '/^Admin(istrative)?(\-| )(Contact )?(Street|Address)[0-9]*$/i',
        'contacts:admin:city' => '/^Admin(istrative)?(\-| )(Contact )?City$/i',
        'contacts:admin:state' => '/^Admin(istrative)?(\-| )(Contact )?State(\/Province)?$/i',
        'contacts:admin:zipcode' => array(
            '/^Admin(istrative)?(\-| )(Contact )?Postal(\-| )Code$/i',
            '/^Admin(istrative)?(\-| )(Contact )?ZIP$/i'
        ),
        'contacts:admin:country' => '/^Admin(istrative)?(\-| )(Contact )?Country(\/Economy)*$/i',
        'contacts:admin:phone' => '/^Admin(istrative)?(\-| )(Contact )?Phone$/i',
        'contacts:admin:fax' => '/^Admin(istrative)?(\-| )(Contact )?FAX$/i',
        'contacts:admin:email' => '/^Admin(istrative)?(\-| )(Contact )?(Email|E-Mail)$/i',
        // Contacts: Tech
        'contacts:tech:handle' => '/^Tech(nical)?(\-| )(Contact )?ID$/i',
        'contacts:tech:name' => '/^Tech(nical)?(\-| )(Contact )?Name$/i',
        'contacts:tech:organization' => '/^Tech(nical)?(\-| )(Contact )?Organization$/i',
        'contacts:tech:address' => '/^Tech(nical)?(\-| )(Contact )?(Street|Address)[0-9]*$/i',
        'contacts:tech:city' => '/^Tech(nical)?(\-| )(Contact )?City$/i',
        'contacts:tech:state' => '/^Tech(nical)?(\-| )(Contact )?State(\/Province)?$/i',
        'contacts:tech:zipcode' => array(
            '/^Tech(nical)?(\-| )(Contact )?Postal(\-| )Code$/i',
            '/^Tech(nical)?(\-| )(Contact )?ZIP$/i'
        ),
        'contacts:tech:country' => '/^Tech(nical)?(\-| )(Contact )?Country(\/Economy)*$/i',
        'contacts:tech:phone' => '/^Tech(nical)?(\-| )(Contact )?Phone$/i',
        'contacts:tech:fax' => '/^Tech(nical)?(\-| )(Contact )?FAX$/i',
        'contacts:tech:email' => '/^Tech(nical)?(\-| )(Contact )?(Email|E-Mail)$/i',
    );

    protected $available = '/No match/i';

    protected $rateLimit = '/exceeded the maximum allowable/i';

}
