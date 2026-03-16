<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Services;

use Composer\Semver\Constraint\MultiConstraint;
use Composer\Semver\Intervals;
use Composer\Semver\VersionParser;
use Exception;
use Github\Exception\InvalidArgumentException;
use Github\Exception\MissingArgumentException;
use LTS\WordpressSecurityAdvisoriesUpgrader\Controllers\GithubApiController;
use LTS\WordpressSecurityAdvisoriesUpgrader\DTO\ConflictSectionUpgradeResult;
use LTS\WordpressSecurityAdvisoriesUpgrader\Services\Wordfence\WordfenceFeedServiceInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;

/**
 * Service to upgrade dependencies
 */
class ComposerConflictsUpgrader
{
    /**
     * Name of repository's default branch
     */
    public const REPO_DEFAULT_BRANCH_NAME = 'master';

    /**
     * Path to composer.json renovating file
     */
    public const COMPOSER_JSON_PATH = 'composer.json';

    /**
     * @var array Contents of composer.json file
     */
    protected array $composer_json_content;

    /**
     * @param GithubApiController           $github_api_controller
     * @param LoggerInterface               $logger
     * @param WordfenceFeedServiceInterface $wordfence_feed_service
     * @param VersionParser                 $version_parser
     */
    public function __construct(
        protected readonly GithubApiController $github_api_controller,
        protected readonly LoggerInterface $logger,
        protected readonly WordfenceFeedServiceInterface $wordfence_feed_service,
        protected readonly VersionParser $version_parser = new VersionParser(),
    ) {
    }

    /**
     * @param int $pause
     *
     * @throws Throwable
     * @return void
     */
    public function renovate(int $pause = 1): void
    {
        $this->logger->debug(sprintf('PHP max_execution_time set to %1$s', ini_get('max_execution_time')));

        $file_content = $this->github_api_controller->getFileContent(static::COMPOSER_JSON_PATH);
        $this->logger->info('Got composer.json from repo!');

        $this->composer_json_content = json_decode($file_content, associative: true, flags: JSON_THROW_ON_ERROR);
        $this->logger->info('Successfully parsed composer.json from repo!');

        $updated_composer_json_content = $this->composer_json_content;
        $feed                          = $this->wordfence_feed_service->getProductionFeed();

        $this->logger->info('Got production feed!');

        foreach ($feed as $entry) {
            $entry_id = $entry['id'] ?? 'unknown';
            if (empty($entry['software'])) {
                $this->logger->warning(sprintf('Got empty $entry["software"] for id=%1$s; CONTINUE', $entry_id));
                continue;
            }

            $upgrade_result = $this->upgradeConflictsForVulnerability($entry, $updated_composer_json_content);
            if (!$upgrade_result instanceof ConflictSectionUpgradeResult || !$upgrade_result->isUpgraded()) {
                $this->logger->notice(sprintf('Not upgraded for id=%1$s', $entry_id));
                continue;
            }
            $updated_composer_json_content = $upgrade_result->getComposerJsonContent();

//            try {
//                $this->tryToCreatePullRequest($entry, $upgrade_result);
//                $this->logger->notice('!!! === Pull Request created === !!!');
//                sleep($pause);
//                continue;
//            } catch (Exception $e) {
//                $this->logger->warning(
//                    sprintf(
//                        'Something went wrong with id=%1$s, details: %2$s ; CONTINUE',
//                        $entry_id,
//                        $e->getMessage()
//                    )
//                );
//                continue;
//            }
        }

        $new_composer_json_content = json_encode(
            value: $updated_composer_json_content,
            flags: JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );
        file_put_contents('composer.json.mockedcomposer', $new_composer_json_content);
    }

    /**
     * Tries to create pull request on selected repository for passed $entry and with $upgraded_result
     *
     * @param array                        $entry          Entry for which PR is created
     * @param ConflictSectionUpgradeResult $upgrade_result Result of composer upgrade conflict section for this $entry
     *
     * @throws InvalidArgumentException
     * @throws MissingArgumentException
     * @throws RuntimeException
     * @return void
     */
    protected function tryToCreatePullRequest(array $entry, ConflictSectionUpgradeResult $upgrade_result): void
    {
        $new_composer_json_content = $upgrade_result->getComposerJsonContent();
        $encoded                   = json_encode(
            value: $new_composer_json_content,
            flags: JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );
        $branch_name               = $entry['id'] ?? md5(json_encode($entry['software']));

        $software      = $entry['software'];
        $software_type = (string)($software[0]['type'] ?? 'unknown type');
        $software_name = (string)($software[0]['name'] ?? 'unknown name');
        $cvss          = (string)($entry['cvss']['score'] ?? 'unknown');

        $this->logger->info(sprintf('Trying to renovate %1$s', $software_name));

        $commit_message = sprintf(
            '%1$s %2$s | CVSS = %3$s | %4$s',
            $software_type,
            $software_name,
            $cvss,
            $upgrade_result->getConflictVersionsString() ?? '',
        );

        $this->logger->info('Creating branch...');
        $this->github_api_controller->createBranch($branch_name, static::REPO_DEFAULT_BRANCH_NAME);

        $this->logger->info('Updating file...');
        $this->github_api_controller->updateFileContent(
            static::COMPOSER_JSON_PATH,
            $encoded,
            $commit_message,
            $this->github_api_controller->getFileSha(
                static::COMPOSER_JSON_PATH,
                static::REPO_DEFAULT_BRANCH_NAME
            ),
            $branch_name
        );

        $this->logger->info('Creating Pull Request...');
        $this->github_api_controller->createPullRequest(
            static::REPO_DEFAULT_BRANCH_NAME,
            $branch_name,
            $commit_message,
            sprintf(
                "According to [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/), %1\$s %2\$s has a %3\$s CVSS security vulnerability\n\nI'm bumping versions to %4\$s\n\nReferences: %5\$s",
                $software_type,
                $software_name,
                $cvss,
                $upgrade_result->getConflictVersionsString() ?? '',
                implode(' , ', $entry['references'] ?? [])
            )
        );
    }

    /**
     * Upgrades composer.json conflict section for specified vulnerability.
     *
     * @param array $entry
     * @param array $composer_json_content
     *
     * @return ConflictSectionUpgradeResult|null
     */
    protected function upgradeConflictsForVulnerability(
        array $entry,
        array $composer_json_content
    ): ?ConflictSectionUpgradeResult {
        $entry_id = $entry['id'] ?? 'unknown';
        $software = $entry['software'];
        if (empty($software)) {
            return null;
        }

        foreach ($software as $software_entry) {
            $upgraded = false;
            $slug     = $software_entry['slug'];
            if (!is_string($slug) || $slug === '') {
                $this->logger->warning(sprintf('$entry["software"] has no slug! id=%1$s', $entry_id));
                continue;
            }

            $affected_versions = $software_entry['affected_versions'] ?? [];
            if (!is_array($affected_versions) || empty($affected_versions)) {
                $this->logger->warning(sprintf('software %1$s has no affected_versions!', $slug));
                continue;
            }

            $entry_type = $software_entry['type'];
            switch ($entry_type) {
                case 'plugin':
                case 'theme':
                    $vulnerability_key =
                        strtolower(sprintf('wpackagist-%1$s/%2$s', $entry_type, $slug));

                    break;

                case 'core':
                    if ($slug !== 'wordpress') {
                        break;
                    }

                    $vulnerability_key = 'roots/wordpress';

                    break;

                default:
                    break;
            }

            if (!isset($vulnerability_key)) {
                $this->logger->warning(sprintf('Unknown software type=%1$s', $entry_type));
                continue;
            }

            foreach ($affected_versions as $key => $affected_version) {
                $conflict_versions_string = $this->getConflictStringForAffectedVersion($affected_version);
                if (!isset($conflict_versions_string)) {
                    $this->logger->warning(
                        sprintf(
                            'Couldn\'t create conflict versions string for affected_versions[%1$s] of package=%2$s',
                            $key,
                            $slug
                        )
                    );
                    continue;
                }

                // Splitting the current version string in the conflict section
                $current_conflict_version = (string)($composer_json_content['conflict'][$vulnerability_key] ?? '');
                if (!$current_conflict_version) {
                    // If the conflict string doesn't exist yet, simply add it
                    $composer_json_content['conflict'][$vulnerability_key] = $conflict_versions_string;
                    $upgraded                                              = true;
                    continue;
                }

                // Checking if the new version is fully covered by the old version
                if ($this->isConflictCoveredBy($current_conflict_version, $conflict_versions_string)) {
                    continue;
                }

                // Checking if the old version is fully covered by the new version
                if ($this->isConflictCoveredBy($current_conflict_version, $conflict_versions_string)) {
                    $composer_json_content['conflict'][$vulnerability_key] = $conflict_versions_string;
                    $upgraded                                              = true;
                    continue;
                }

                // If versions intersects
                if ($this->isConflictIntersectedBy($current_conflict_version, $conflict_versions_string)) {
                    $composer_json_content['conflict'][$vulnerability_key] =
                        $this->mergeIntersectedConflictString($current_conflict_version, $conflict_versions_string);
                    $upgraded                                              = true;
                    continue;
                }

                // Adding the new version to an existing string
                $composer_json_content['conflict'][$vulnerability_key] .= " || {$conflict_versions_string}";
                $upgraded                                              = true;
            }

            if ($upgraded) {
                ksort($composer_json_content['conflict']);
            }
        }

        return new ConflictSectionUpgradeResult(
            $composer_json_content,
            $conflict_versions_string ?? '',
            $upgraded ?? false
        );
    }

    /**
     * Gets the string of conflicts versions in format like:
     *  >2.0.0,<=2.0.3
     *  >=1.0.4,<2.0.0
     *  <=3.0.5
     *
     * @param array $affected_version
     *
     * @return string|null
     */
    protected function getConflictStringForAffectedVersion(array $affected_version): ?string
    {
        $to_version = $affected_version['to_version'] ?? null;
        if (!$to_version) {
            return null;
        }
        $from_version = $affected_version['from_version'] ?? '*';

        if (!$this->isValidComposerVersion($from_version) || !$this->isValidComposerVersion($to_version)) {
            return null;
        }

        $from_symbol = ($affected_version['from_inclusive'] ?? null)
            ? '>='
            : '>';
        $to_symbol   = ($affected_version['to_inclusive'] ?? null)
            ? '<='
            : '<';

        return match (true) {
            $from_version === $to_version => $from_version,
            $from_version === '*'         => sprintf('%1$s%2$s', $to_symbol, $to_version),
            default                       => sprintf(
                '%1$s%2$s,%3$s%4$s',
                $from_symbol,
                $from_version,
                $to_symbol,
                $to_version
            ),
        };
    }

    /**
     * Whether passed string is a valid composer.json version of a package
     *
     * @param string $version
     *
     * @return bool
     */
    private function isValidComposerVersion(string $version): bool
    {
        try {
            $this->version_parser->parseConstraints($version);

            return true;
        } catch (Exception $e) {
            $this->logger->warning(sprintf('Version %1$s is not a correct version', $version));

            return false;
        }
    }

    /**
     * @param string $conflict
     * @param string $new_conflict
     *
     * @return bool
     */
    private function isConflictCoveredBy(string $conflict, string $new_conflict): bool
    {
        $new_constraint      = $this->version_parser->parseConstraints($new_conflict);
        $existing_constraint = $this->version_parser->parseConstraints($conflict);

        return Intervals::isSubsetOf($new_constraint, $existing_constraint);
    }

    /**
     * @param string $conflict
     * @param string $new_conflict
     *
     * @return bool
     */
    private function isConflictIntersectedBy(string $conflict, string $new_conflict): bool
    {
        $new_constraint      = $this->version_parser->parseConstraints($new_conflict);
        $existing_constraint = $this->version_parser->parseConstraints($conflict);

        return Intervals::haveIntersections($new_constraint, $existing_constraint);
    }

    /**
     * @param string $conflict
     * @param string $new_conflict
     *
     * @return string
     */
    private function mergeIntersectedConflictString(string $conflict, string $new_conflict): string
    {
        $new_constraint      = $this->version_parser->parseConstraints($new_conflict);
        $existing_constraint = $this->version_parser->parseConstraints($conflict);
        $multi_constraint    = MultiConstraint::create([$new_constraint, $existing_constraint], false);
        $conflict_string     = Intervals::compactConstraint($multi_constraint)->getPrettyString();

        return str_replace(['[', ']'], '', $conflict_string);
    }
}
