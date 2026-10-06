<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Controllers;

use Github\Client;
use Github\Exception\InvalidArgumentException;
use Github\Exception\MissingArgumentException;
use JsonException;
use RuntimeException;

/**
 * Class to fetch data from GitHub API via its Client
 */
final class GithubApiController
{
    /**
     * @var string|null Head's repository owner
     */
    protected ?string $head_repo_owner = null;

    /**
     * @var string|null Head's repository name
     */
    protected ?string $head_repo_name = null;


    /**
     * @param string $repo_owner Repository owner + next param
     * @param string $repo_name  Repository name that needs to be renovated
     * @param Client $client     GitHub API client
     */
    public function __construct(
        protected readonly Client $client,
        protected readonly string $repo_owner,
        protected readonly string $repo_name
    ) {
    }

    /**
     * Returns actual repository name (one that PR will be created in)
     *
     * @return string
     */
    public function getActualRepositoryName(): string
    {
        return $this->head_repo_name ?? $this->repo_name;
    }

    /**
     * Returns actual repository owner (one that PR will be created in)
     *
     * @return string
     */
    public function getActualRepositoryOwner(): string
    {
        return $this->head_repo_owner ?? $this->repo_owner;
    }

    /**
     * Sets head_repo to which PRs should be submitted
     *
     * @param string $head_repo_owner
     * @param string $head_repo_name
     *
     * @return $this
     */
    public function setHeadRepository(string $head_repo_owner, string $head_repo_name): self
    {
        $this->head_repo_owner = $head_repo_owner;
        $this->head_repo_name  = $head_repo_name;

        return $this;
    }

    /**
     * Tries to branch `$branch_name` and head it to `$from_branch`.
     * Throws a RuntimeException if unable to do so.
     *
     * @param string $branch_name
     * @param string $from_branch
     *
     * @throws MissingArgumentException
     * @throws RuntimeException
     * @return void
     */
    public function createBranch(string $branch_name, string $from_branch): void
    {
        $ref_name = sprintf('refs/heads/%1$s', $branch_name);
        $ref_data = [
            'ref' => $ref_name,
            'sha' => $this->getBranchSha($from_branch),
        ];

        $response = $this->client
            ->api('gitData')
            ->references()
            ->create($this->getActualRepositoryOwner(), $this->getActualRepositoryName(), $ref_data);

        if (is_array($response) && $response['ref'] === $ref_name) {
            return;
        }

        throw new RuntimeException(sprintf('Unable to create branch, GitHub response was: %1$s', $response));
    }

    /**
     * Returns branch SHA
     *
     * @param string $branch_name
     *
     * @throws RuntimeException
     * @return string
     */
    public function getBranchSha(string $branch_name): string
    {
        $reference = $this->client
            ->api('gitData')
            ->references()
            ->show($this->getActualRepositoryOwner(), $this->getActualRepositoryName(), sprintf('heads/%1$s', $branch_name));

        if (!is_array($reference)) {
            throw new RuntimeException(sprintf('Unable to retrieve sha information for branch: %1$s', $branch_name));
        }

        $sha = $reference['object']['sha'] ?? null;

        if (!isset($sha)) {
            throw new RuntimeException(sprintf('Unable to retrieve sha information for branch: %1$s', $branch_name));
        }

        return $sha;
    }

    /**
     * Returns selected branch/file SHA
     *
     * @param string $path_to_file
     * @param string $branch
     *
     * @throws RuntimeException
     * @return string
     */
    public function getFileSha(string $path_to_file, string $branch): string
    {
        $response = $this->client
            ->api('repo')
            ->contents()
            ->show($this->getActualRepositoryOwner(), $this->getActualRepositoryName(), $path_to_file, $branch);
        $sha      = $response['sha'] ?? null;
        if (is_string($sha)) {
            return $sha;
        }

        throw new RuntimeException(sprintf('Unable to retrieve file SHA: %1$s', $path_to_file));
    }

    /**
     * Retrieves remote repository's file content
     *
     * @param string $path_to_file Full path to the file
     *
     * @throws JsonException
     * @throws RuntimeException
     * @return string
     */
    public function getFileContent(string $path_to_file): string
    {
        $file_data = $this->client
            ->api('repo')
            ->contents()
            ->show($this->getActualRepositoryOwner(), $this->getActualRepositoryName(), $path_to_file);
        if (!$file_data || !isset($file_data['content'])) {
            throw new RuntimeException(sprintf('Missing "%1$s" content', $path_to_file));
        }

        switch (true) {
            case (!empty($file_data['content'])):
                $decoded_data = base64_decode(string: $file_data['content'], strict: true);
                if (!is_string($decoded_data)) {
                    throw new RuntimeException(sprintf('Could not base64_decode "%1$s" content', $path_to_file));
                }

                return $decoded_data;

            case (!empty($file_data['download_url'])):
                return file_get_contents($file_data['download_url']);

            default:
                throw new RuntimeException('Could not get composer.json content from repo!');
        }
    }

    /**
     * @param string $path_to_file
     * @param string $content
     * @param string $commit_message
     * @param string $old_sha
     * @param string $branch
     *
     * @throws MissingArgumentException
     * @return void
     */
    public function updateFileContent(
        string $path_to_file,
        string $content,
        string $commit_message,
        string $old_sha,
        string $branch
    ): void {
        $this->client
            ->api('repo')
            ->contents()
            ->update($this->getActualRepositoryOwner(), $this->getActualRepositoryName(), $path_to_file, $content, $commit_message, $old_sha, $branch);
    }

    /**
     * Creates a pull request from `$head_branch` to `$base_branch`
     *
     * @param string $base_branch
     * @param string $head_branch
     * @param string $title
     * @param string $body
     *
     * @throws InvalidArgumentException
     * @throws MissingArgumentException
     * @return void
     */
    public function createPullRequest(string $base_branch, string $head_branch, string $title, string $body = ''): void
    {
        $actual_head_branch = isset($this->head_repo_owner, $this->head_repo_name)
            ? sprintf('%1$s:%2$s', $this->head_repo_owner, $head_branch)
            : $head_branch;

        $this->client
            ->api('pull_request')
            ->create($this->repo_owner, $this->repo_name, [
                'base'  => $base_branch,
                'head'  => $actual_head_branch,
                'title' => $title,
                'body'  => $body,
            ]);
    }
}
