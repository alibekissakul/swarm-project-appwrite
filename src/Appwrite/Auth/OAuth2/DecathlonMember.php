<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

class DecathlonMember extends OAuth2
{
    /**
     * @var string
     */
    private string $endpoint = 'https://api-global.preprod.decathlon.net';

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
        'profile',
    ];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'decathlonMember';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return $this->endpoint . '/connect/oauth/authorize?' . \http_build_query([
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
            $this->tokens = \json_decode($this->request(
                'POST',
                $this->endpoint . '/connect/oauth/token',
                [],
                \http_build_query([
                    'client_id' => $this->appID,
                    'redirect_uri' => $this->callback,
                    'client_secret' => $this->appSecret,
                    'code' => $code,
                    'grant_type' => 'authorization_code',
                ])
            ), true);
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
        $headers = ['Authorization: Basic ' . base64_encode($this->appID . ':' . $this->appSecret)];

        $this->tokens = \json_decode($this->request(
            'POST',
            $this->endpoint . '/connect/oauth/token',
            $headers,
            \http_build_query([
                'scope' => \implode(' ', $this->getScopes()),
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ])
        ), true);

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

        $identifiers = $user['identifiers'];

        // Looking for loyalty card number as ID
        $result = \array_filter(
            $identifiers,
            fn($identifier) => $identifier['id'] === 'loyalty_card'
        );

        return $result ? $result[0]['value'] : $user['sub'];
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['claims']['email'] ?? '';
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
        $user = $this->getUser($accessToken);

        return $user['claims']['email_verified'] ?? false;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return \trim($user['claims']['given_name'] . ' ' . $user['claims']['family_name']);
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $headers = [
                'x-api-key: 3821ded8-89f2-420b-832c-4e0ae56eb91c',
                'Authorization: Bearer ' . \urlencode($accessToken),
            ];

            $this->user = \json_decode($this->request(
                'GET',
                $this->endpoint . '/identity/v1/members/profile/me',
                $headers
            ), true);
        }

        return $this->user;
    }
}
