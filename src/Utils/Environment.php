<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Utils;

final class Environment
{
    /**
     * @return string
     */
    public static function getWordfenceProductionFeedUrl(): string
    {
        return self::getEnv('WORDFENCE_PRODUCTION_FEED_URL');
    }

    /**
     * @return string
     */
    public static function getWordfenceScannerFeedUrl(): string
    {
        return self::getEnv('WORDFENCE_SCANNER_FEED_URL');
    }

    /**
     * @return string
     */
    public static function getWordfenceApiKey(): string
    {
        return self::getEnv('WORDFENCE_API_KEY');
    }

    /**
     * @param string $env_name
     *
     * @return string
     */
    private static function getEnv(string $env_name): string
    {
        $env = getenv($env_name);

        return $env
            ? (string)$env
            : '';
    }
}
