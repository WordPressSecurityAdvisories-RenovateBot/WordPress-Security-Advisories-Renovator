<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Services\Wordfence;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\HttpFactory;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;

/**
 * Service for Wordfence API
 */
class WordfenceFeedService implements WordfenceFeedServiceInterface
{
    /**
     * @param string                  $api_key
     * @param string                  $scanner_feed_url
     * @param string                  $production_feed_url
     * @param ClientInterface         $client
     * @param RequestFactoryInterface $request_factory
     */
    public function __construct(
        protected readonly string $api_key,
        protected readonly string $scanner_feed_url,
        protected readonly string $production_feed_url,
        protected readonly ClientInterface $client = new Client(),
        protected readonly RequestFactoryInterface $request_factory = new HttpFactory(),
    ) {
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     * @throws ClientExceptionInterface
     * @inheritdoc
     */
    public function getProductionFeed(): array
    {
        return $this->getSelectedFeed($this->production_feed_url);
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     * @throws ClientExceptionInterface
     * @inheritdoc
     */
    public function getScannerFeed(): array
    {
        return $this->getSelectedFeed($this->scanner_feed_url);
    }

    /**
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @return array{
     *     software: array{
     *         type: string,
     *         name: string,
     *         slug: string,
     *         affected_versions: array,
     *     }[]
     * }[]
     */
    protected function getSelectedFeed(string $feed): array
    {
        $request = $this->request_factory
            ->createRequest('GET', $feed)
            ->withHeader('Authorization', 'Bearer ' . $this->api_key)
            ->withHeader('Accept', 'application/json');

        $response = $this->client->sendRequest($request);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException(
                sprintf('Wordfence API returned status %d', $response->getStatusCode())
            );
        }

        $body = (string)$response->getBody();

        return json_decode(
            json: $body,
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
    }
}
