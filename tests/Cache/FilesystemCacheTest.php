<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Test\Cache;

use Hvatum\OpenIDConnect\Client\Cache\FilesystemCache;
use PHPUnit\Framework\TestCase;

class FilesystemCacheTest extends TestCase
{
    private string $cacheDir;
    private FilesystemCache $cache;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir() . '/oidc-cache-test-' . uniqid();
        $this->cache = new FilesystemCache($this->cacheDir);
    }

    protected function tearDown(): void
    {
        $files = glob($this->cacheDir . '/*');
        if ($files) {
            array_map('unlink', $files);
        }
        if (is_dir($this->cacheDir)) {
            @rmdir($this->cacheDir);
        }
    }

    public function testSetAndGet(): void
    {
        $this->cache->set('key1', ['foo' => 'bar'], 3600);
        self::assertSame(['foo' => 'bar'], $this->cache->get('key1'));
    }

    public function testGetReturnsDefaultForMissingKey(): void
    {
        self::assertNull($this->cache->get('nonexistent'));
        self::assertSame('fallback', $this->cache->get('nonexistent', 'fallback'));
    }

    public function testExpiredEntryReturnsDefault(): void
    {
        // Write a cache file with an already-expired timestamp
        $file = $this->cacheDir . '/expired.cache';
        @mkdir($this->cacheDir, 0700, true);
        file_put_contents($file, json_encode([
            'expires' => time() - 10,
            'data' => 'old',
        ]));

        self::assertNull($this->cache->get('expired'));
        // File should be cleaned up
        self::assertFileDoesNotExist($file);
    }

    public function testNullTtlMeansNoExpiry(): void
    {
        $this->cache->set('forever', 'value');
        self::assertSame('value', $this->cache->get('forever'));
    }

    public function testZeroTtlExpiresImmediately(): void
    {
        $this->cache->set('zero-ttl', 'value', 0);
        self::assertNull($this->cache->get('zero-ttl'));
    }

    public function testNegativeTtlExpiresImmediately(): void
    {
        $this->cache->set('negative-ttl', 'value', -10);
        self::assertNull($this->cache->get('negative-ttl'));
    }

    public function testGetPreservesCachedNullValue(): void
    {
        $this->cache->set('nullable', null, 3600);
        $file = $this->cacheDir . '/nullable.cache';
        self::assertFileExists($file);

        self::assertNull($this->cache->get('nullable', 'fallback'));
        self::assertFileExists($file, 'null value entries must not be treated as corrupt');
    }

    public function testHasReturnsTrueForCachedNullValue(): void
    {
        $this->cache->set('nullable-has', null, 3600);
        self::assertTrue($this->cache->has('nullable-has'));
    }

    public function testSetRejectsInvalidKeyWithDirectoryTraversalCharacters(): void
    {
        $this->expectException(\Psr\SimpleCache\InvalidArgumentException::class);
        $this->cache->set('../escape', 'value', 3600);
    }

    public function testGetRejectsInvalidKeyWithPathSeparator(): void
    {
        $this->expectException(\Psr\SimpleCache\InvalidArgumentException::class);
        $this->cache->get('nested/key');
    }

    public function testDelete(): void
    {
        $this->cache->set('to-delete', 'data', 3600);
        self::assertTrue($this->cache->has('to-delete'));

        $this->cache->delete('to-delete');
        self::assertFalse($this->cache->has('to-delete'));
    }

    public function testDeleteNonexistentKeyReturnsTrue(): void
    {
        self::assertTrue($this->cache->delete('does-not-exist'));
    }

    public function testClear(): void
    {
        $this->cache->set('a', 1, 3600);
        $this->cache->set('b', 2, 3600);

        $this->cache->clear();

        self::assertNull($this->cache->get('a'));
        self::assertNull($this->cache->get('b'));
    }

    public function testHas(): void
    {
        self::assertFalse($this->cache->has('key'));
        $this->cache->set('key', 'val', 3600);
        self::assertTrue($this->cache->has('key'));
    }

    public function testGetMultiple(): void
    {
        $this->cache->set('x', 1, 3600);
        $this->cache->set('y', 2, 3600);

        $result = $this->cache->getMultiple(['x', 'y', 'z'], 'default');
        self::assertSame(['x' => 1, 'y' => 2, 'z' => 'default'], $result);
    }

    public function testSetMultiple(): void
    {
        $this->cache->setMultiple(['a' => 'alpha', 'b' => 'beta'], 3600);
        self::assertSame('alpha', $this->cache->get('a'));
        self::assertSame('beta', $this->cache->get('b'));
    }

    public function testDeleteMultiple(): void
    {
        $this->cache->set('d1', 1, 3600);
        $this->cache->set('d2', 2, 3600);
        $this->cache->deleteMultiple(['d1', 'd2']);
        self::assertNull($this->cache->get('d1'));
        self::assertNull($this->cache->get('d2'));
    }

    public function testDateIntervalTtl(): void
    {
        $this->cache->set('interval', 'data', new \DateInterval('PT1H'));
        self::assertSame('data', $this->cache->get('interval'));
    }

    public function testDateIntervalWithDaysIsRejected(): void
    {
        $this->expectException(\Psr\SimpleCache\InvalidArgumentException::class);
        $this->cache->set('interval-days', 'data', new \DateInterval('P1D'));
    }

    public function testDateIntervalWithMonthsIsRejected(): void
    {
        $this->expectException(\Psr\SimpleCache\InvalidArgumentException::class);
        $this->cache->set('interval-months', 'data', new \DateInterval('P1M'));
    }

    public function testDateIntervalWithYearsIsRejected(): void
    {
        $this->expectException(\Psr\SimpleCache\InvalidArgumentException::class);
        $this->cache->set('interval-years', 'data', new \DateInterval('P1Y'));
    }

    public function testInvertedDateIntervalIsRejected(): void
    {
        $interval = new \DateInterval('PT10S');
        $interval->invert = 1;

        $this->expectException(\Psr\SimpleCache\InvalidArgumentException::class);
        $this->cache->set('interval-inverted', 'data', $interval);
    }

    public function testCorruptFileReturnsDefault(): void
    {
        @mkdir($this->cacheDir, 0700, true);
        file_put_contents($this->cacheDir . '/corrupt.cache', 'not-json');
        self::assertNull($this->cache->get('corrupt'));
    }

    public function testDirectoryCreatedWithCorrectPermissions(): void
    {
        $this->cache->set('trigger', 'create-dir', 3600);
        self::assertDirectoryExists($this->cacheDir);
        // Check permissions (0700)
        $perms = fileperms($this->cacheDir) & 0777;
        self::assertSame(0700, $perms);
    }

    public function testFileCreatedWithRestrictedPermissions(): void
    {
        $this->cache->set('perm-test', 'data', 3600);
        $file = $this->cacheDir . '/perm-test.cache';
        self::assertFileExists($file);
        $perms = fileperms($file) & 0777;
        self::assertSame(0600, $perms);
    }
}
