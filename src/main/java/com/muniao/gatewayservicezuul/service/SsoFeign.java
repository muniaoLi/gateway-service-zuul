package com.muniao.gatewayservicezuul.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@FeignClient(name = "sso-server", path = "/")
public interface SsoFeign
{
    /**
     * 判断key是否存在
     */
    @RequestMapping("redis/hasKey/{key}")
    Boolean hasKey(@PathVariable("key") String key);
}
