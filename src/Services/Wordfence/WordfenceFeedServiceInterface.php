<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Services\Wordfence;

use Exception;
use Throwable;

/**
 * Interface of controller that should act like a Wordfence API proxy
 */
interface WordfenceFeedServiceInterface
{
    /**
     * @throws Throwable
     * @return array{
     *     software: array{
     *         type: string,
     *         name: string,
     *         slug: string,
     *         affected_versions: array,
     *     }[]
     * }[]
     */
    public function getScannerFeed(): array;

    /**
     * @throws Throwable
     * @return array{
     *     software: array{
     *         type: string,
     *         name: string,
     *         slug: string,
     *         affected_versions: array,
     *     }[],
     *     references: string[],
     *     cvss: array{
     *          score: float|null,
     *     },
     * }[]
     */
    public function getProductionFeed(): array;
}
