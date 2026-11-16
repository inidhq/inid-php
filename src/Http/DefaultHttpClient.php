<?php

declare(strict_types=1);

namespace InID\Http;

// curl when the extension is there; PHP's own streams otherwise (no extension needed)
final class DefaultHttpClient implements HttpClient
{
    public function request(string $method, string $url, array $headers = [], ?string $body = null, float $timeout = 10.0): HttpResponse
    {
        return function_exists('curl_init') ? $this->curl($method, $url, $headers, $body, $timeout) : $this->stream($method, $url, $headers, $body, $timeout);
    }

    private function curl(string $method, string $url, array $headers, ?string $body, float $timeout): HttpResponse
    {
        $handle = curl_init($url);
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = "$name: $value";
        }
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int) (min($timeout, 5.0) * 1000),
        ]);
        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }
        $result = curl_exec($handle);
        if ($result === false) {
            $error = curl_error($handle);
            curl_close($handle);
            throw new NetworkException("InID can't be reached: $error");
        }
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        return new HttpResponse($status, (string) $result);
    }

    private function stream(string $method, string $url, array $headers, ?string $body, float $timeout): HttpResponse
    {
        $lines = '';
        foreach ($headers as $name => $value) {
            $lines .= "$name: $value\r\n";
        }
        $context = stream_context_create(['http' => [
            'method' => $method,
            'header' => $lines,
            'content' => $body ?? '',
            'timeout' => $timeout,
            // InID's 4xx answers carry the reason; they aren't failures to reach it
            'ignore_errors' => true,
            'follow_location' => 0,
        ]]);
        $result = @file_get_contents($url, false, $context);
        // PHP 8.4 offers http_get_last_response_headers(); older ones fill this local variable
        $responseHeaders = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
        if ($result === false || !$responseHeaders) {
            throw new NetworkException("InID can't be reached: " . (error_get_last()['message'] ?? 'no answer'));
        }
        // The last status line wins (after any 100 Continue)
        $status = 0;
        foreach ($responseHeaders as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1];
            }
        }
        return new HttpResponse($status, $result);
    }
}
