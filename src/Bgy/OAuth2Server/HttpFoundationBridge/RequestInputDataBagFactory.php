<?php
/**
 * @author Boris Guéry <guery.b@gmail.com>
 */

namespace Bgy\OAuth2Server\HttpFoundationBridge;

use Bgy\OAuth2\InputDataBag;
use Symfony\Component\HttpFoundation\Request;

class RequestInputDataBagFactory
{
    public static function fromRequest(Request $request)
    {
        return new InputDataBag(
            array_merge_recursive(
                $request->query->all(),
                $request->request->all()
            )
        );
    }
}
