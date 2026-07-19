<?php
/**
 * Laika Auth
 * Author: Showket Ahmed
 * Email: riyadhtayf@gmail.com
 * License: MIT
 * This file is part of the Laika PHP MVC Framework.
 * For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Laika\Auth\Providers;

use Laika\Auth\Interfaces\OauthProviderInterface;

class GoogleOauthProvider implements OauthProviderInterface
{
    /** @var string Facebook Client ID */
    protected string $clientId;

    /** @var string Facebook Client Secret */
    protected string $clientSecret;

    public function __construct(string $clientId, string $clientSecret)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }


    /**
     * Provider Name
     * @return string
     */
    public function name(): string
    {
        return 'google';
    }

    /**
     * Provider Auth Url
     * @param string $redirectUri App Rediret Url
     * @param array $scopes User Informations From Provider
     * @return string
     */
    public function getAuthUrl(string $redirectUri, array $scopes = []): string
    {
        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $scopes ?: ['openid', 'email', 'profile']),
            'access_type' => 'offline',
            'prompt' => 'consent',
        ];

        return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params);
    }

    /**
     * Get Provider Access Token
     * @param string $code
     * @param string $redirectUri
     * @return array
     */
    public function getAccessToken(string $code, string $redirectUri): array
    {
        $ch = curl_init('https://oauth2.googleapis.com/token');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ]),
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response, true) ?? [];
    }

    /**
     * Get User Profile
     * @param string $accessToken
     * @return array
     */
    public function getUserProfile(string $accessToken): array
    {
        $ch = curl_init('https://www.googleapis.com/oauth2/v2/userinfo');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ["Authorization: Bearer {$accessToken}"],
        ]);

        $response = curl_exec($ch);
        curl_close($ch);
        $data = json_decode($response, true) ?? [];

        return [
            'id' => $data['id'] ?? null,
            'email' => $data['email'] ?? null,
            'name' => $data['name'] ?? null,
            'avatar' => $data['picture'] ?? null,
        ];
    }
}
