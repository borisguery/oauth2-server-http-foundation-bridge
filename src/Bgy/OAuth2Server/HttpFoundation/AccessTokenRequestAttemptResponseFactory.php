<?php
/**
 * @author Boris Guéry <guery.b@gmail.com>
 */

namespace Bgy\OAuth2Server\HttpFoundation;


use Bgy\OAuth2\FailedTokenRequestAttemptResult;
use Bgy\OAuth2\GrantType\GrantError;
use Bgy\OAuth2\SuccessfulTokenRequestAttemptResult;
use Bgy\OAuth2\TokenRequestAttemptResult;
use Symfony\Component\HttpFoundation\JsonResponse;

class AccessTokenRequestAttemptResponseFactory
{
    public static function createJsonResponse(TokenRequestAttemptResult $attemptResult)
    {
        if ($attemptResult instanceof SuccessfulTokenRequestAttemptResult) {
            $httpStatusCode = 200;
            $rawResponse = [
                'access_token'  => $attemptResult->getAccessToken()->getToken(),
                'expires_in'    => $attemptResult->getAccessToken()->getExpiresAt()->format('U') - date('U'),
                'token_type'    => 'bearer',
                'refresh_token' => $attemptResult->getRefreshToken()
                    ? $attemptResult->getRefreshToken()->getToken()
                    : null,
            ];
        } elseif ($attemptResult instanceof FailedTokenRequestAttemptResult) {
            $rawResponse = [
                'error'             => (string) $attemptResult->getGrantDecision()->getError(),
                'error_description' => $attemptResult->getGrantDecision()->getError()->getErrorDescription(),
                'error_uri'         => $attemptResult->getGrantDecision()->getError()->getErrorUri(),
            ];

            switch ($attemptResult->getGrantDecision()->getError()) {
                case GrantError::ACCESS_DENIED:
                    $httpStatusCode = 403;
                    break;
                case GrantError::INVALID_REQUEST:
                    $httpStatusCode = 400;
                    break;
                case GrantError::INVALID_SCOPE:
                    $httpStatusCode = 403;
                    break;
                case GrantError::INVALID_GRANT:
                    $httpStatusCode = 401;
                    break;
                case GrantError::TEMPORARILY_UNAVAILABLE:
                    $httpStatusCode = 503;
                    break;
                case GrantError::UNAUTHORIZED_CLIENT:
                    $httpStatusCode = 401;
                    break;
                case GrantError::UNSUPPORTED_RESPONSE_TYPE:
                    $httpStatusCode = 400;
                    break;
                case GrantError::SERVER_ERROR:
                default:
                    $httpStatusCode = 500;
                    break;
            }
        } else {
            // should never happen
            $rawResponse = [
                'error' => 'Unknown error',
                'error_description' => null,
            ];
            $httpStatusCode = 500;
        }

        return new JsonResponse($rawResponse, $httpStatusCode);
    }
}
