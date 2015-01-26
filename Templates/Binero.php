<?php

namespace Novutec\WhoisParser\Templates;

use Novutec\WhoisParser\Templates\Type\Regex;

class Binero extends Regex
{

    protected $blocks = array(
        0 => '/^Domain Information\n[\=]+\n(.*?)\n\n/ims',
        1 => '/^Owner-c:?\n[\=]+\n(.*?)\n\n/ims',
        2 => '/^Admin-c:?\n[\=]+\n(.*?)\n\n/ims',
        3 => '/^Tech-c:?\n[\=]+\n(.*?)\n\n/ims',
        4 => '/^Billing-c:?\n[\=]+\n(.*?)\n\n/ims',
        // There's a nameservers section, but it may be unpopulated (haven't seen it populated yet)
    );

    protected $blockItems = array(
        0 => array(
            '/^Domain[\.\s]+:(.*)$/im' => 'name',
            '/^Created[\.\s]+:(.*)$/im' => 'created',
            '/^Modified[\.\s]+:(.*)$/im' => 'changed',
            '/^Expires[\.\s]+:(.*)$/im' => 'expires',
            '/^Registrar[\.\s]+:(.*)$/im' => 'registrar:name',
            '/^DNSSEC[\.\s]+:(.*)$/im' => 'dnssec',
        ),
        1 => array(
            '/^Organization[\.\s]+:(.*)$/im' => 'contacts:owner:organization',
            '/^Name[\.\s]+:(.*)$/im' => 'contacts:owner:name',
            '/^Address( [0-9]+)?[\.\s]+:(.*)$/im' => 'contacts:owner:address',
            '/^Zip[\.\s]+:(.*)$/im' => 'contacts:owner:zipcode',
            '/^City[\.\s]+:(.*)$/im' => 'contacts:owner:city',
            '/^State[\.\s]+:(.*)$/im' => 'contacts:owner:state',
            '/^Country[\.\s]+:(.*)$/im' => 'contacts:owner:country',
            '/^Phone[\.\s]+:(.*)$/im' => 'contacts:owner:phone',
            '/^Fax[\.\s]+:(.*)$/im' => 'contacts:owner:fax',
            '/^E-mail[\.\s]+:(.*)$/im' => 'contacts:owner:email',
        ),
        2 => array(
            '/^Organization[\.\s]+:(.*)$/im' => 'contacts:admin:organization',
            '/^Name[\.\s]+:(.*)$/im' => 'contacts:admin:name',
            '/^Address( [0-9]+)?[\.\s]+:(.*)$/im' => 'contacts:admin:address',
            '/^Zip[\.\s]+:(.*)$/im' => 'contacts:admin:zipcode',
            '/^City[\.\s]+:(.*)$/im' => 'contacts:admin:city',
            '/^State[\.\s]+:(.*)$/im' => 'contacts:admin:state',
            '/^Country[\.\s]+:(.*)$/im' => 'contacts:admin:country',
            '/^Phone[\.\s]+:(.*)$/im' => 'contacts:admin:phone',
            '/^Fax[\.\s]+:(.*)$/im' => 'contacts:admin:fax',
            '/^E-mail[\.\s]+:(.*)$/im' => 'contacts:admin:email',
        ),
        3 => array(
            '/^Organization[\.\s]+:(.*)$/im' => 'contacts:tech:organization',
            '/^Name[\.\s]+:(.*)$/im' => 'contacts:tech:name',
            '/^Address( [0-9]+)?[\.\s]+:(.*)$/im' => 'contacts:tech:address',
            '/^Zip[\.\s]+:(.*)$/im' => 'contacts:tech:zipcode',
            '/^City[\.\s]+:(.*)$/im' => 'contacts:tech:city',
            '/^State[\.\s]+:(.*)$/im' => 'contacts:tech:state',
            '/^Country[\.\s]+:(.*)$/im' => 'contacts:tech:country',
            '/^Phone[\.\s]+:(.*)$/im' => 'contacts:tech:phone',
            '/^Fax[\.\s]+:(.*)$/im' => 'contacts:tech:fax',
            '/^E-mail[\.\s]+:(.*)$/im' => 'contacts:tech:email',
        ),
        4 => array(
            '/^Organization[\.\s]+:(.*)$/im' => 'contacts:billing:organization',
            '/^Name[\.\s]+:(.*)$/im' => 'contacts:billing:name',
            '/^Address( [0-9]+)?[\.\s]+:(.*)$/im' => 'contacts:billing:address',
            '/^Zip[\.\s]+:(.*)$/im' => 'contacts:billing:zipcode',
            '/^City[\.\s]+:(.*)$/im' => 'contacts:billing:city',
            '/^State[\.\s]+:(.*)$/im' => 'contacts:billing:state',
            '/^Country[\.\s]+:(.*)$/im' => 'contacts:billing:country',
            '/^Phone[\.\s]+:(.*)$/im' => 'contacts:billing:phone',
            '/^Fax[\.\s]+:(.*)$/im' => 'contacts:billing:fax',
            '/^E-mail[\.\s]+:(.*)$/im' => 'contacts:billing:email',
        ),
    );
}