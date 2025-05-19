<?php

namespace AlibabaCloud\Credentials\Request;

use AlibabaCloud\Credentials\Credentials;
use AlibabaCloud\Credentials\Utils\Helper;
use AlibabaCloud\Credentials\Configure\Config;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use AlibabaCloud\Tea\Response;
use Psr\Http\Message\ResponseInterface;

use Exception;
use InvalidArgumentException;

/**
 * RESTful RPC Request.
 */
class Request
{

    /**
     * Request Connect Timeout
     */
    const CONNECT_TIMEOUT = 5;

    /**
     * Request Read Timeout
     */
    const READ_TIMEOUT = 5;

    /**
     * @var array
     */
    private static $config = [];


    /**
     *
     * @return array
     */
    public static function commonOptions()
    {
        $options = [];
        $options['http_errors'] = false;
        $options['connect_timeout'] = self::CONNECT_TIMEOUT;
        $options['read_timeout'] = self::READ_TIMEOUT;
        $options['headers']['User-Agent'] = Helper::getUserAgent();

        // Turn on debug mode based on environment variable.
        if (strtolower(Helper::env('DEBUG')) === 'sdk') {
            $options['debug'] = true;
        }
        return $options;
    }

    /**
     * @param string $salt
     *
     * @return string
     */
    public static function uuid($salt)
    {
        return md5($salt . uniqid(md5(microtime(true)), true));
    }

    /**
     * @param string $method
     * @param array  $parameters
     *
     * @return string
     */
    public static function signString($method, array $parameters)
    {
        ksort($parameters);
        $canonicalized = '';
        foreach ($parameters as $key => $value) {
            $canonicalized .= '&' . self::percentEncode($key) . '=' . self::percentEncode($value);
        }

        return $method . '&%2F&' . self::percentEncode(substr($canonicalized, 1));
    }

    public static function getAuthorization($pathname, $method, $query, $headers, $payload, $ak, $secret, $product, $region, $date)
    {
        $signingkey = self::getSigningkey($secret, $product, $region, $date);
        $signature = self::getSignature($pathname, $method, $query, $headers, $payload, $signingkey);
        $signedHeaders = self::getSignedHeaders($headers);
        $signedHeadersStr = implode(";", $signedHeaders);
        return Config::SIGNATURE_TYPE_PREFIX . "HMAC-SHA256 Credential=" . $ak . "/" . $date . "/" . $region . "/" . $product . "/" . Config::SIGN_PREFIX . "_request,SignedHeaders=" . $signedHeadersStr . ",Signature=" . $signature;
    }

    /**
     * @param string $pathname
     * @param string $method
     * @param string[] $query
     * @param string[] $headers
     * @param string $payload
     * @param int[] $signingkey
     * @return string
     */
    public static function getSignature($pathname, $method, $query, $headers, $payload, $signingkey)
    {
        $canonicalURI = "/";
        if ($pathname !== null && $pathname !== "") {
            $canonicalURI = $pathname;
        }
        $stringToSign = "";
        $canonicalizedResource = self::buildCanonicalizedResource($query);
        $canonicalizedHeaders = self::buildCanonicalizedHeaders($headers);
        $signedHeaders = self::getSignedHeaders($headers);
        $signedHeadersStr = implode(";", $signedHeaders);
        $stringToSign = $method . "\n" . $canonicalURI . "\n" . $canonicalizedResource . "\n" . $canonicalizedHeaders . "\n" . $signedHeadersStr . "\n" . $payload;
        $hex = self::hexEncode(self::hashWithSha256(Helper::toBytes($stringToSign)));
        $stringToSign = Config::SIGNATURE_TYPE_PREFIX . "HMAC-SHA256\n" . $hex;
        $signature = self::shaHmac256signByBytes($stringToSign, $signingkey);
        return self::hexEncode($signature);
    }

    /**
     * @param string $secret
     * @param string $product
     * @param string $region
     * @param string $date
     * @return array
     */
    private static function getSigningkey($secret, $product, $region, $date)
    {
        $sc1 = Helper::toBytes(Config::SIGN_PREFIX . $secret);
        $sc2 = self::shaHmac256signByBytes($date, $sc1);
        $sc3 = self::shaHmac256signByBytes($region, $sc2);
        $sc4 = self::shaHmac256signByBytes($product, $sc3);
        return self::shaHmac256signByBytes(Config::SIGN_PREFIX . "_request", $sc4);
    }

    /**
     * @param string $product
     * @param string $endpoint
     * @param string $regionId
     * @return string
     */
    public static function getRegion($endpoint)
    {
        $region = "center";
        if ($endpoint === null || $endpoint === "") {
            return $region;
        }
        $preRegion = str_replace(Config::ENDPOINT_SUFFIX, "", $endpoint);
        $nodes = explode(".", $preRegion);
        if (\count($nodes) === 2) {
            $region = @$nodes[1];
        }
        return $region;
    }

    /**
     * @param string[] $query
     * @return string
     */
    private static function buildCanonicalizedResource($query)
    {
        $canonicalizedResource = "";
        if ($query !== null) {
            $queryArray = array_keys($query);
            sort($queryArray);
            $separator = "";
            foreach ($queryArray as $key) {
                $canonicalizedResource = $canonicalizedResource . $separator . self::percentEncode($key) . "=";
                if (isset($query[$key])) {
                    $canonicalizedResource = $canonicalizedResource . self::percentEncode(@$query[$key]);
                }
                $separator = "&";
            }
        }
        return $canonicalizedResource;
    }

    /**
     * @param string[] $headers
     * @return string
     */
    private static function buildCanonicalizedHeaders($headers)
    {
        $canonicalizedHeaders = "";
        $sortedHeaders = self::getSignedHeaders($headers);
        foreach ($sortedHeaders as $header) {
            $canonicalizedHeaders = $canonicalizedHeaders . $header . ":" . trim($headers[$header]) . "\n";
        }
        return $canonicalizedHeaders;
    }

    /**
     * @param string[] $headers
     * @return array
     */
    private static function getSignedHeaders($headers)
    {
        $headersArray = array_keys($headers);
        sort($headersArray);
        $signedHeaders = [];
        foreach ($headersArray as $key) {
            $lowerKey = strtolower($key);
            if (0 === strpos($lowerKey, "x-acs-")) {
                if (\in_array($lowerKey, $signedHeaders)) {
                    array_push($signedHeaders, $lowerKey);
                }
            }
        }
        return $signedHeaders;
    }

    /**
     * @param string $string
     * @param string $accessKeySecret
     *
     * @return string
     */
    public static function shaHmac1sign($string, $accessKeySecret)
    {
        return base64_encode(hash_hmac('sha1', $string, $accessKeySecret, true));
    }

    /**
     * @param string $string
     * @param string $accessKeySecret
     *
     * @return string
     */
    public static function shaHmac256sign($string, $accessKeySecret)
    {
        return base64_encode(hash_hmac('sha256', $string, $accessKeySecret, true));
    }

    /**
     * @param string $string
     * @param array $secret bytes
     *
     * @return array
     */
    private static function shaHmac256signByBytes($string, $secret)
    {
        return Helper::toBytes(hash_hmac('sha256', $string, Helper::toString($secret), true));
    }

    /**
     * @param string $string
     * @param string $privateKey
     *
     * @return string
     */
    public static function shaHmac256WithRsasign($string, $privateKey)
    {
        $binarySignature = '';
        try {
            openssl_sign(
                $string,
                $binarySignature,
                $privateKey,
                \OPENSSL_ALGO_SHA256
            );
        } catch (Exception $exception) {
            throw new InvalidArgumentException(
                $exception->getMessage()
            );
        }

        return base64_encode($binarySignature);
    }

    /**
     * @param string $string
     *
     * @return null|string|string[]
     */
    private static function percentEncode($string)
    {
        $result = rawurlencode($string);
        $result = str_replace(['+', '*'], ['%20', '%2A'], $result);
        $result = preg_replace('/%7E/', '~', $result);

        return $result;
    }

    /**
     * @param int[] $raw
     * @return string
     */
    public static function hexEncode($raw)
    {
        if (empty($raw)) {
            throw new \InvalidArgumentException('not a valid value for parameter');
        }
        $ret = '';
        foreach ($raw as $i => $b) {
            $str = dechex($b);
            if (strlen($str) < 2) {
                $str = str_pad($str, 2, '0', STR_PAD_LEFT);
            }
            $ret .= $str;
        }
        return $ret;
    }

    /**
     * @param int[] $raw
     * @return int[] hashed bytes
     */
    public static function hashWithSha256($raw)
    {
        $str = Helper::toString($raw);
        $res = hash('sha256', $str, true);
        return Helper::toBytes($res);
    }

    /**
     * @return Client
     * @throws Exception
     */
    public static function createClient()
    {
        if (Credentials::hasMock()) {
            $stack = HandlerStack::create(Credentials::getMock());
            $history = Credentials::getHandlerHistory();
            $stack->push($history);
        } else {
            $stack = HandlerStack::create();
        }

        $stack->push(Middleware::mapResponse(static function (ResponseInterface $response) {
            return new Response($response);
        }));

        self::$config['handler'] = $stack;

        return new Client(self::$config);
    }
}
