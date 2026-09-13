<?php

declare(strict_types=1);

namespace Lock\Server\Support\Setup;

final readonly class EnvironmentFile
{
    public function __construct(private ?string $path = null) {}

    /**
     * Atomically upsert the given variables into the environment file.
     *
     * @param  array<string, string>  $variables
     *
     * @throws EnvironmentWriteException
     */
    public function write(array $variables): void
    {
        $path = $this->path ?? app()->environmentFilePath();
        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw new EnvironmentWriteException("Unable to read the environment file at [{$path}].");
        }

        foreach ($variables as $name => $value) {
            $contents = $this->upsert($contents, $name, $value);
        }

        $mode = is_file($path) ? (fileperms($path) & 0777) : 0600;
        $temp = $path.'.'.bin2hex(random_bytes(6)).'.tmp';

        if (@file_put_contents($temp, $contents, LOCK_EX) === false) {
            @unlink($temp);

            throw new EnvironmentWriteException("Unable to write the environment file at [{$path}].");
        }

        @chmod($temp, $mode);

        if (! @rename($temp, $path)) {
            @unlink($temp);

            throw new EnvironmentWriteException("Unable to write the environment file at [{$path}].");
        }
    }

    public function value(string $key): ?string
    {
        $path = $this->path ?? app()->environmentFilePath();
        $contents = @file_get_contents($path);

        if ($contents === false
            || preg_match('/^'.preg_quote($key, '/').'=(.*)$/m', $contents, $matches) !== 1) {
            return null;
        }

        $value = trim($matches[1]);

        if (preg_match('/^"(.*)"$/s', $value, $quoted) === 1) {
            return str_replace(['\n', '\"', '\\\\'], ["\n", '"', '\\'], $quoted[1]);
        }

        if (preg_match("/^'(.*)'$/s", $value, $quoted) === 1) {
            return $quoted[1];
        }

        $value = trim((string) preg_replace('/\s+#.*$/', '', $value));

        return $value === '' ? null : $value;
    }

    private function upsert(string $contents, string $name, string $value): string
    {
        $line = $name.'='.$value;
        $pattern = '/^'.preg_quote($name, '/').'=.*$/m';

        if (preg_match($pattern, $contents) === 1) {
            return (string) preg_replace($pattern, $line, $contents, 1);
        }

        return rtrim($contents, "\n")."\n".$line."\n";
    }
}
