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

class FacebookOauthProvider implements OauthProviderInterface
{
    /** @var string Facebook Client ID */
    protected string $clientId;

    /** @var string Facebook Client Secret */
    protected string $clientSecret;

    /** @var string Facebook Graph Version */
    protected string $graphVersion = 'v19.0';

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
        return 'facebook';
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
            'scope' => implode(',', $scopes ?: ['email', 'public_profile']),
        ];

        return "https://www.facebook.com/{$this->graphVersion}/dialog/oauth?" . http_build_query($params);
    }

    /**
     * Get Provider Access Token
     * @param string $code
     * @param string $redirectUri
     * @return array
     */
    public function getAccessToken(string $code, string $redirectUri): array
    {
        $params = http_build_query([
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $redirectUri,
            'code' => $code,
        ]);

        $ch = curl_init("https://graph.facebook.com/{$this->graphVersion}/oauth/access_token?{$params}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
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
        $params = http_build_query([
            'fields' => 'id,name,email,picture',
            'access_token' => $accessToken,
        ]);

        $ch = curl_init("https://graph.facebook.com/me?{$params}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);
        $data = json_decode($response, true) ?? [];

        return [
            'id' => $data['id'] ?? null,
            'email' => $data['email'] ?? null,
            'name' => $data['name'] ?? null,
            'avatar' => $data['picture']['data']['url'] ?? null,
        ];
    }
}
