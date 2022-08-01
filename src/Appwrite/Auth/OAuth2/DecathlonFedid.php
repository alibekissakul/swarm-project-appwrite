<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

class DecathlonFedid extends OAuth2
{
    /**
     * @var string
     */
    private string $endpoint = 'https://preprod.idpdecathlon.oxylane.com';

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
        'openid',
        'profile',
    ];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'decathlonFedid';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return $this->endpoint . '/as/authorization.oauth2?' . \http_build_query([
                'client_id' => $this->appID,
                'redirect_uri' => $this->callback,
                'response_type' => 'code',
                'scope' => \implode(' ', $this->getScopes()),
                'state' => \json_encode($this->state),
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
            $headers = [
                'Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret),
                'Content-Type: application/x-www-form-urlencoded',
                'Cache-Control: no-cache',
            ];

            $this->tokens = \json_decode($this->request(
                'POST',
                $this->endpoint . '/as/token.oauth2',
                $headers,
                \http_build_query([
                    'grant_type' => 'authorization_code',
                    'client_id' => $this->appID,
                    'code' => $code,
                    'redirect_uri' => $this->callback,
                    'scope' => \implode(' ', $this->getScopes()),
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
        $headers = [
            'Cache-Control: no-cache',
            'Content-Type: application/x-www-form-urlencoded',
        ];

        $this->tokens = \json_decode($this->request(
            'POST',
            $this->endpoint . '/as/token.oauth2',
            $headers,
            \http_build_query([
                'client_id' => $this->appID,
                'client_secret' => $this->appSecret,
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

        var_dump($user);

        return $user['uid'] ?? '';
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
    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $headers = ['Authorization: Bearer ' . \urlencode($accessToken)];

            $this->user = \json_decode($this->request(
                'POST',
                $this->endpoint . '/idp/userinfo.openid',
                $headers,
                \http_build_query([
                    'scope' => \implode(' ', $this->getScopes()),
                ])
            ), true);
        }

        return $this->user;
    }
}
