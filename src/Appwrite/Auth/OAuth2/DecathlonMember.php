<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

class DecathlonMember extends OAuth2
{
    /**
     * @var array
     */
    protected array $user = [];

    /**
     * @var array
     */
    protected array $tokens = [];

    /**
     * @var array
     */
    protected array $scopes = [
        'account:store',
        'account:shipping_address',
        'account:profile',
        'account:consent',
        'account:address',
        'account:gender',
        'purchases',
        'account:email',
        'account:sports',
        'account:birthdate',
        'account:phone',
        'account:locale',
        'country',
        'timezone',
        'identifiers',
        'profile'
    ];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'decathlon-member';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return 'https://api-global.preprod.decathlon.net/connect/oauth/authorize?' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'response_type' => 'code',
            'state' => \json_encode($this->state),
            'scope' => \implode(' ', $this->getScopes()),
        ]);
    }

    /**
     * @param string $code
     *
     * @return array
     */
    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $response = $this->request(
                'POST',
                'https://api-global.preprod.decathlon.net/connect/oauth/token',
                [],
                \http_build_query([
                    'client_id' => $this->appID,
                    'redirect_uri' => $this->callback,
                    'client_secret' => $this->appSecret,
                    'code' => $code,
                    'grant_type' => 'authorization_code'
                ])
            );

            $output = [];
            \parse_str($response, $output);
            $this->tokens = $output;
        }

        return $this->tokens;
    }

    /**
     * @param string $refreshToken
     *
     * @return array
     */
    public function refreshTokens(string $refreshToken): array
    {
        $response = $this->request(
            'POST',
            'https://api-global.preprod.decathlon.net/connect/oauth/token',
            [
                'Authorization: Basic ' . base64_encode($this->appID . ':' . $this->appSecret)
            ],
            \http_build_query([
                'scope' => \implode(' ', $this->getScopes()),
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ])
        );

        $output = [];
        \parse_str($response, $output);
        $this->tokens = $output;

        if (empty($this->tokens['refresh_token'])) {
            $this->tokens['refresh_token'] = $refreshToken;
        }

        return $this->tokens;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['id'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['mail'] ?? '';
    }

    /**
     * Check if the OAuth email is verified
     *
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        return true;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['displayName'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken)
    {
        if (empty($this->user)) {
            $this->user = \json_decode($this->request(
                'GET',
                'https://api-global.preprod.decathlon.net/identity/v1/members/profile/me',
                [
                    'x-api-key' => '3821ded8-89f2-420b-832c-4e0ae56eb91c',
                    'Authorization: Bearer ' . \urlencode($accessToken)
                ]
            ), true);
        }

        return $this->user;
    }
}
