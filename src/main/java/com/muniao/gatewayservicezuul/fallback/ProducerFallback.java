package com.muniao.gatewayservicezuul.fallback;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.netflix.zuul.filters.route.FallbackProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

@Component
public class ProducerFallback implements FallbackProvider
{
    private final Logger logger = LoggerFactory.getLogger(FallbackProvider.class);

    //指定要处理的 service。
    @Override
    public String getRoute()
    {
        return "server-producer";
    }

    private ClientHttpResponse fallbackResponse()
    {
        return new ClientHttpResponse()
        {
            @Override
            public HttpStatus getStatusCode()
            {
                return HttpStatus.OK;
            }

            @Override
            public int getRawStatusCode()
            {
                return 200;
            }

            @Override
            public String getStatusText()
            {
                return "OK";
            }

            @Override
            public void close()
            {

            }

            @Override
            public InputStream getBody()
            {
                return new ByteArrayInputStream("The service is unavailable.".getBytes());
            }

            @Override
            public HttpHeaders getHeaders()
            {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                return headers;
            }
        };
    }

    @Override
    public ClientHttpResponse fallbackResponse(String route, Throwable cause)
    {
        if (cause != null && cause.getCause() != null)
        {
            String reason = cause.getCause().getMessage();
            logger.info("Excption {}", reason);
        }
        return fallbackResponse();
    }
}