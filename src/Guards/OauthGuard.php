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

namespace Laika\Auth\Guards;

use Laika\Auth\Interfaces\OauthProviderInterface;
use Laika\Auth\Model\OuthModel;

class OauthGuard
{
    /** @var OauthProviderInterface Provider */
    protected OauthProviderInterface $provider;

    /** @var TokenGuard Token Guard */
    protected TokenGuard $tokenGuard;

    /** @var OuthModel Outh Model */
    protected OuthModel $model;

    /** @var string User Model */
    protected string $userModel;

    public function __construct(OauthProviderInterface $provider, TokenGuard $tokenGuard, string $userModel)
    {
        $this->provider = $provider;
        $this->tokenGuard = $tokenGuard;
        $this->userModel = $userModel;
        $this->model = new OuthModel();
    }

    /**
     * Get Provider Redirect Url
     * @param string $redirectUri App Redirect Url
     * @param array $scopes User Data to Get From Provider
     * @return string
     */
    public function redirect(string $redirectUri, array $scopes = []): string
    {
        return $this->provider->getAuthUrl($redirectUri, $scopes);
    }

    /**
     * Provider Callback
     * @param string $code Request Code From Url. Example: $_GET['code']
     * @param string $redirectUri App Redirect Url
     * @return array
     */
    public function callback(string $code, string $redirectUri): array
    {
        $tokenData = $this->provider->getAccessToken($code, $redirectUri);
        $accessToken = $tokenData['access_token'] ?? null;

        if (!$accessToken) {
            throw new \RuntimeException('OAuth token exchange failed.');
        }

        $profile = $this->provider->getUserProfile($accessToken);
        $user = $this->findOrCreateUser($profile, $tokenData);

        $issued = $this->tokenGuard->issueToken($user->id);

        return [
            'user' => $user,
            'token' => $issued['token'],
        ];
    }

    ######################################################################################
    /*================================== INTERNAL API ==================================*/
    ######################################################################################
    /**
     * Find or Create Outh User
     * @param array $profile
     * @param array $tokenData
     * @return array
     */
    protected function findOrCreateUser(array $profile, array $tokenData): array
    {
        $outh = $this->model
                    ->where(['provider' => $this->provider->name(), 'provider_user_id' => $profile['id']])
                    ->first();

        $uModel = new $this->userModel;
        if ($oauth) {
            $this->updateOauthTokens($oauth->id, $tokenData);
            return $uModel->where([$uModel->id => $oauth['user_id']])->first();
        }

        $user = $uModel->firstOrCreate(
            ['email' => $profile['email']],
            ['name' => $profile['name'], 'email' => $profile['email']]
        );

        $row = [
            'user_id' => $user['id'],
            'provider' => $this->provider->name(),
            'provider_user_id' => $profile['id'],
            'access_token' => $tokenData['access_token'] ?? null,
            'refresh_token' => $tokenData['refresh_token'] ?? null,
            'avatar' => $profile['avatar'] ?? null,
            'email' => $profile['email'] ?? null,
            'name' => $profile['name'] ?? null,
            'expires_at' => isset($tokenData['expires_in']) ? date('Y-m-d H:i:s', time() + $tokenData['expires_in']) : null,
            'created_at' => date('Y-m-d H:i:s')
        ];
        $this->model->insert();

        return $user;
    }

    /**
     * Update Outh Token
     * @param int $oauthId
     * @param array $tokenData
     * @return array
     */
    protected function updateOauthTokens(int $oauthId, array $tokenData): void
    {
        $this->model
            ->where([$this->model->id => $oauthId])
            ->update([
                'access_token' => $tokenData['access_token'] ?? null,
                'refresh_token' => $tokenData['refresh_token'] ?? null
                ]);
    }
}
