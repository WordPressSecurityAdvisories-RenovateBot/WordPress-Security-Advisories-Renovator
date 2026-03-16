<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Services\Wordfence;

/**
 * Mock for WordfenceController to work with it locally
 */
class MockFilesystemWordfenceFeedService implements WordfenceFeedServiceInterface
{
    /**
     * @inheritdoc
     */
    public function getScannerFeed(string $filename = 'Scanner_Feed.mockedfeed'): array
    {
        return json_decode(
            json: file_get_contents($filename),
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
    }

    /**
     * @inheritdoc
     */
    public function getProductionFeed(string $filename = 'Production_Feed.mockedfeed'): array
    {
        return json_decode(
            json: file_get_contents($filename),
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
    }
}
