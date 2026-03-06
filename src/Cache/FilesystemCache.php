<?php

declare(strict_types=1);

namespace Hvatum\OpenIDConnect\Client\Cache;

use Psr\SimpleCache\CacheInterface;

/**
 * Minimal PSR-16 filesystem cache.
 *
 * Stores each entry as a JSON file with an embedded expiry timestamp.
 * Used as the default cache when no PSR-16 implementation is provided.
 */
class FilesystemCache implements CacheInterface
{
    public function __construct(
        private readonly string $cacheDir
    ) {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->validateKey($key);
        $file = $this->filePath($key);

        if (!file_exists($file)) {
            return $default;
        }

        $content = @file_get_contents($file);
        if ($content === false) {
            return $default;
        }

        $entry = json_decode($content, true);
        if (!is_array($entry) || !isset($entry['expires']) || !array_key_exists('data', $entry)) {
            @unlink($file);
            return $default;
        }

        if ($entry['expires'] !== 0 && $entry['expires'] < time()) {
            @unlink($file);
            return $default;
        }

        return $entry['data'];
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->validateKey($key);
        $seconds = $this->ttlToSeconds($ttl);

        // PSR-16: zero or negative TTL means the item is expired
        if ($seconds !== null && $seconds <= 0) {
            return $this->delete($key);
        }

        $this->ensureDirectory();

        $entry = [
            'expires' => $seconds !== null ? time() + $seconds : 0,
            'data' => $value,
        ];

        $content = json_encode($entry, JSON_UNESCAPED_SLASHES);
        if ($content === false) {
            return false;
        }

        $result = @file_put_contents($this->filePath($key), $content, \LOCK_EX);
        if ($result !== false) {
            @chmod($this->filePath($key), 0600);
        }

        return $result !== false;
    }

    public function delete(string $key): bool
    {
        $this->validateKey($key);
        $file = $this->filePath($key);
        if (file_exists($file)) {
            return @unlink($file);
        }
        return true;
    }

    public function clear(): bool
    {
        $files = glob($this->cacheDir . '/*.cache');
        if ($files === false) {
            return false;
        }
        foreach ($files as $file) {
            @unlink($file);
        }
        return true;
    }

    public function has(string $key): bool
    {
        $sentinel = new \stdClass();
        return $this->get($key, $sentinel) !== $sentinel;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }
        return $result;
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        $success = true;
        foreach ($values as $key => $value) {
            if (!$this->set($key, $value, $ttl)) {
                $success = false;
            }
        }
        return $success;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $success = true;
        foreach ($keys as $key) {
            if (!$this->delete($key)) {
                $success = false;
            }
        }
        return $success;
    }

    private function validateKey(string $key): void
    {
        if ($key === '' || preg_match('#[{}()/\\\\@:]#', $key)) {
            throw new InvalidArgumentException(
                sprintf('Invalid cache key: "%s". Keys must not be empty or contain {}()/\\@: characters.', $key)
            );
        }
    }

    private function filePath(string $key): string
    {
        return $this->cacheDir . '/' . $key . '.cache';
    }

    private function ensureDirectory(): void
    {
        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0700, true);
        }
    }

    private function ttlToSeconds(null|int|\DateInterval $ttl): ?int
    {
        if ($ttl === null) {
            return null;
        }
        if ($ttl instanceof \DateInterval) {
            if ($ttl->invert === 1 || $ttl->y !== 0 || $ttl->m !== 0 || $ttl->d !== 0) {
                throw new InvalidArgumentException(
                    'DateInterval TTL only supports time-based values (hours/minutes/seconds)'
                );
            }

            return ($ttl->h * 3600) + ($ttl->i * 60) + $ttl->s;
        }
        return $ttl;
    }
}
